import sys
import os
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                            QLabel, QLineEdit, QPushButton, QMessageBox, QGridLayout,
                            QFileDialog, QTabWidget, QProgressBar, QHBoxLayout, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QIcon
from calcular_hash import HashLogica

class HashCalculatorThread(QThread):
    finished = pyqtSignal(dict)
    error = pyqtSignal(str)
    progress = pyqtSignal()

    def __init__(self, file_path):
        super().__init__()
        self.file_path = file_path
        self.hash_logic = HashLogica()

    def run(self):
        try:
            result = self.hash_logic.calculate_file_hash(
                self.file_path, self.progress.emit)
            self.finished.emit(result)
        except Exception as e:
            self.error.emit(str(e))

class DropLineEdit(QLineEdit):
    def __init__(self):
        super().__init__()
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            self.setText(files[0])

class HashGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.hash_logic = HashLogica()
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Calculador de hash")
        self.setFixedSize(980, 425)
        self.setWindowIcon(QIcon('icono.png'))    

        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Crear pestañas
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)

        # Pestaña de texto
        text_tab = QWidget()
        tab_widget.addTab(text_tab, "Texto")
        self.setup_text_tab(text_tab)

        # Pestaña de archivo
        file_tab = QWidget()
        tab_widget.addTab(file_tab, "Archivo")
        self.setup_file_tab(file_tab)

        # Pestaña de verificación
        verify_tab = QWidget()
        tab_widget.addTab(verify_tab, "Verificar")
        self.setup_verify_tab(verify_tab)

        self.apply_styles()

    def setup_text_tab(self, tab):
        layout = QVBoxLayout(tab)
        
        # Input
        input_layout = QHBoxLayout()
        self.text_input = QLineEdit()
        calc_button = QPushButton("Calcular")
        calc_button.clicked.connect(self.calculate_text_hash)
        input_layout.addWidget(QLabel("Texto:"))
        input_layout.addWidget(self.text_input)
        input_layout.addWidget(calc_button)
        layout.addLayout(input_layout)

        # Resultados
        self.text_results = {}
        results_layout = QGridLayout()
        for i, algo in enumerate(['md5', 'sha1', 'sha224', 'sha256', 
                                'sha384', 'sha512', 'blake2b', 'blake2s']):
            label = QLabel(f"{algo.upper()}:")
            result = QLineEdit()
            result.setReadOnly(True)
            copy_btn = QPushButton("Copiar")
            copy_btn.clicked.connect(lambda x, r=result: self.copy_to_clipboard(r.text()))
            
            results_layout.addWidget(label, i, 0)
            results_layout.addWidget(result, i, 1)
            results_layout.addWidget(copy_btn, i, 2)
            
            self.text_results[algo] = result

        layout.addLayout(results_layout)
        layout.addStretch()

    def setup_file_tab(self, tab):
        layout = QVBoxLayout(tab)

        # File selection
        file_layout = QHBoxLayout()
        self.file_input = DropLineEdit()
        self.file_input.setPlaceholderText("Arrastra un archivo aquí o selecciónalo...")
        self.file_input = DropLineEdit()
        self.file_input.setReadOnly(True) 
        browse_button = QPushButton("Explorar")
        browse_button.clicked.connect(self.browse_file)
        calc_file_button = QPushButton("Calcular")
        calc_file_button.clicked.connect(self.calculate_file_hash)
        
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(browse_button)
        file_layout.addWidget(calc_file_button)
        layout.addLayout(file_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        # Results
        self.file_results = {}
        results_layout = QGridLayout()
        for i, algo in enumerate(['md5', 'sha1', 'sha224', 'sha256', 
                                'sha384', 'sha512', 'blake2b', 'blake2s']):
            label = QLabel(f"{algo.upper()}:")
            result = QLineEdit()
            result.setReadOnly(True)
            copy_btn = QPushButton("Copiar")
            copy_btn.clicked.connect(lambda x, r=result: self.copy_to_clipboard(r.text()))
            
            results_layout.addWidget(label, i, 0)
            results_layout.addWidget(result, i, 1)
            results_layout.addWidget(copy_btn, i, 2)
            
            self.file_results[algo] = result

        layout.addLayout(results_layout)
        layout.addStretch()

    def setup_verify_tab(self, tab):
        layout = QVBoxLayout(tab)

        # Primer archivo
        file1_layout = QHBoxLayout()
        self.verify_file1_input = DropLineEdit()
        self.verify_file1_input.setReadOnly(True)
        self.verify_file1_input.setPlaceholderText("Selecciona el primer archivo...")
        browse_button1 = QPushButton("Explorar")
        browse_button1.clicked.connect(lambda: self.browse_verify_file(1))
        file1_layout.addWidget(QLabel("Archivo 1:"))
        file1_layout.addWidget(self.verify_file1_input)
        file1_layout.addWidget(browse_button1)
        layout.addLayout(file1_layout)

        # Segundo archivo
        file2_layout = QHBoxLayout()
        self.verify_file2_input = DropLineEdit()
        self.verify_file2_input.setReadOnly(True)
        self.verify_file2_input.setPlaceholderText("Selecciona el segundo archivo...")
        browse_button2 = QPushButton("Explorar")
        browse_button2.clicked.connect(lambda: self.browse_verify_file(2))
        file2_layout.addWidget(QLabel("Archivo 2:"))
        file2_layout.addWidget(self.verify_file2_input)
        file2_layout.addWidget(browse_button2)
        layout.addLayout(file2_layout)

        # Separación visual
        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator)

        # Botón para comparar archivos
        compare_button = QPushButton("Comparar archivos")
        compare_button.clicked.connect(self.compare_files)
        compare_button.setFixedWidth(200)  
        layout.addWidget(compare_button, alignment=Qt.AlignmentFlag.AlignCenter)

        # Resultado de la verificación
        result_layout = QVBoxLayout()
        
        # Etiqueta para el estado de la verificación
        self.verify_status_label = QLabel()
        self.verify_status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.verify_status_label.setStyleSheet("""
            QLabel {
                padding: 10px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
        """)
        result_layout.addWidget(self.verify_status_label)

        # Etiqueta para los detalles
        self.verify_details_label = QLabel()
        self.verify_details_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.verify_details_label.setWordWrap(True)
        self.verify_details_label.setStyleSheet("""
            QLabel {
                padding: 10px;
                font-size: 12px;
            }
        """)
        result_layout.addWidget(self.verify_details_label)

        layout.addLayout(result_layout)
        layout.addStretch()

    def calculate_text_hash(self):
        text = self.text_input.text()
        if not text:
            QMessageBox.warning(self, "Error", "Por favor ingresa un texto")
            return

        try:
            results = self.hash_logic.calculate_hashes(text)
            for algo, result in results.items():
                self.text_results[algo].setText(result)
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def calculate_file_hash(self):
        file_path = self.file_input.text()
        if not file_path or not os.path.isfile(file_path):
            QMessageBox.warning(self, "Error", "Por favor selecciona un archivo válido")
            return

        self.progress_bar.setRange(0, 0)
        self.thread = HashCalculatorThread(file_path)
        self.thread.finished.connect(self.handle_file_hash_result)
        self.thread.error.connect(self.handle_error)
        self.thread.progress.connect(lambda: self.progress_bar.setValue(
            self.progress_bar.value() + 1))
        self.thread.start()

    def handle_file_hash_result(self, results):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        for algo, result in results.items():
            self.file_results[algo].setText(result)

    def handle_error(self, error_msg):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        QMessageBox.critical(self, "Error", error_msg)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar archivo", "", "Todos los archivos (*.*)")
        if file_path:
            self.file_input.setText(file_path)

    def browse_verify_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Seleccionar archivo", "", "Todos los archivos (*.*)")
        if file_path:
            self.verify_file_input.setText(file_path)

    def verify_hash(self):
        file_path = self.verify_file_input.text()
        expected_hash = self.verify_hash_input.text()

        if not file_path or not os.path.isfile(file_path):
            self.verify_status_label.setText("Error: Archivo no válido")
            self.verify_status_label.setStyleSheet("""
                QLabel {
                    background-color: #ffebee;
                    color: #c62828;
                    padding: 10px;
                    border-radius: 5px;
                    font-size: 14px;
                    font-weight: bold;
                }
            """)
            self.verify_details_label.setText("Por favor selecciona un archivo válido")
            return

        if not expected_hash:
            self.verify_status_label.setText("Error: Hash no proporcionado")
            self.verify_status_label.setStyleSheet("""
                QLabel {
                    background-color: #ffebee;
                    color: #c62828;
                    padding: 10px;
                    border-radius: 5px;
                    font-size: 14px;
                    font-weight: bold;
                }
            """)
            self.verify_details_label.setText("Por favor ingresa un hash para verificar")
            return

        try:
            result = self.hash_logic.verify_file_integrity(file_path, expected_hash)
            
            if result['match']:
                self.verify_status_label.setText("¡VERIFICACIÓN EXITOSA!")
                self.verify_status_label.setStyleSheet("""
                    QLabel {
                        background-color: #e8f5e9;
                        color: #2e7d32;
                        padding: 10px;
                        border-radius: 5px;
                        font-size: 14px;
                        font-weight: bold;
                    }
                """)
                details = (f"El hash del archivo coincide.\n"
                        f"Algoritmo detectado: {result['algorithm'].upper()}\n"
                        f"Hash calculado: {result['calculated_hash']}")
            else:
                self.verify_status_label.setText("¡VERIFICACIÓN FALLIDA!")
                self.verify_status_label.setStyleSheet("""
                    QLabel {
                        background-color: #ffebee;
                        color: #c62828;
                        padding: 10px;
                        border-radius: 5px;
                        font-size: 14px;
                        font-weight: bold;
                    }
                """)
                details = (f"El hash del archivo NO coincide.\n"
                        f"Algoritmo detectado: {result['algorithm'].upper()}\n"
                        f"Hash esperado: {expected_hash}\n"
                        f"Hash calculado: {result['calculated_hash']}")
            
            self.verify_details_label.setText(details)
            self.verify_details_label.setStyleSheet("""
                QLabel {
                    background-color: #f5f5f5;
                    color: #333333;
                    padding: 10px;
                    border-radius: 5px;
                    font-size: 12px;
                }
            """)

        except Exception as e:
            self.verify_status_label.setText("¡ERROR!")
            self.verify_status_label.setStyleSheet("""
                QLabel {
                    background-color: #ffebee;
                    color: #c62828;
                    padding: 10px;
                    border-radius: 5px;
                    font-size: 14px;
                    font-weight: bold;
                }
            """)
            self.verify_details_label.setText(f"Error: {str(e)}")

    def copy_to_clipboard(self, text):
        if text:
            clipboard = QApplication.clipboard()
            clipboard.setText(text)


    def browse_verify_file(self, file_num):
        file_path, _ = QFileDialog.getOpenFileName(
            self, f"Seleccionar archivo {file_num}", "", "Todos los archivos (*.*)")
        if file_path:
            if file_num == 1:
                self.verify_file1_input.setText(file_path)
            else:
                self.verify_file2_input.setText(file_path)

    def compare_files(self):
        file1_path = self.verify_file1_input.text()
        file2_path = self.verify_file2_input.text()

        if not file1_path or not os.path.isfile(file1_path):
            QMessageBox.warning(self, "Error", "Por favor selecciona el primer archivo")
            return
        if not file2_path or not os.path.isfile(file2_path):
            QMessageBox.warning(self, "Error", "Por favor selecciona el segundo archivo")
            return

        try:
            # Calcular hashes de ambos archivos
            hash1 = self.hash_logic.calculate_file_hash(file1_path)
            hash2 = self.hash_logic.calculate_file_hash(file2_path)

            # Comparar los hashes
            matches = all(hash1[algo] == hash2[algo] for algo in hash1.keys())

            if matches:
                self.verify_status_label.setText("¡Los archivos son idénticos!")
                self.verify_status_label.setStyleSheet("""
                    QLabel {
                        background-color: #e8f5e9;
                        color: #2e7d32;
                        padding: 10px;
                        border-radius: 5px;
                        font-weight: bold;
                    }
                """)
            else:
                self.verify_status_label.setText("¡Los archivos son diferentes!")
                self.verify_status_label.setStyleSheet("""
                    QLabel {
                        background-color: #ffebee;
                        color: #c62828;
                        padding: 10px;
                        border-radius: 5px;
                        font-weight: bold;
                    }
                """)

            # Mostrar los hashes de ambos archivos
            details = "Hashes de los archivos:\n\n"
            for algo in hash1.keys():
                details += f"{algo.upper()}:\n"
                details += f"Archivo 1: {hash1[algo]}\n"
                details += f"Archivo 2: {hash2[algo]}\n\n"
            
            self.verify_details_label.setText(details)

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def apply_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
            }
            QLabel {
                font-family: Arial;
                font-size: 12px;
                color: #000000;  
            }
            QLineEdit {
                padding: 5px;
                border: 1px solid #cccccc;
                border-radius: 4px;
                background-color: white;
                color: #000000;  
            }
            QLineEdit:read-only {
                background-color: #f8f8f8;
                color: #000000;  
            }
            QPushButton {
                padding: 5px 10px;
                background-color: #2196F3;  
                color: white;
                border: none;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1976D2;  
            }
            QPushButton:pressed {
                background-color: #0D47A1; 
            }
            QProgressBar {
                border: 1px solid #cccccc;
                border-radius: 4px;
                text-align: center;
                color: #000000;  
            }
            QProgressBar::chunk {
                background-color: #2196F3;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: #ffffff;
            }
            QTabBar::tab {
                background-color: #f0f0f0;
                border: 1px solid #cccccc;
                border-bottom-color: #cccccc;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
                min-width: 8ex;
                padding: 8px;
                color: #000000;  
            }
            QTabBar::tab:selected {
                background-color: #ffffff;
                border-bottom-color: #ffffff;
            }
            QTabBar::tab:hover {
                background-color: #e0e0e0;
            }
            QMessageBox {
                background-color: #ffffff;          
                color: #000000;  
            }
            QMessageBox QPushButton {
                background-color: #ffffff;           
                color: black;           
                min-width: 70px;
            }
        """)

def main():
    app = QApplication(sys.argv)
    window = HashGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
