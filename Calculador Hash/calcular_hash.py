import hashlib
from hashlib import blake2b, blake2s

class HashLogica:
    @staticmethod
    def calculate_hashes(texto):
        #Calcula los hashes de un texto.
        try:
            encoded_text = texto.encode('utf-8')
            return {
                'md5': hashlib.md5(encoded_text).hexdigest(),
                'sha1': hashlib.sha1(encoded_text).hexdigest(),
                'sha224': hashlib.sha224(encoded_text).hexdigest(),
                'sha256': hashlib.sha256(encoded_text).hexdigest(),
                'sha384': hashlib.sha384(encoded_text).hexdigest(),
                'sha512': hashlib.sha512(encoded_text).hexdigest(),
                'blake2b': blake2b(encoded_text).hexdigest(),
                'blake2s': blake2s(encoded_text).hexdigest()
            }
        except Exception as e:
            raise Exception(f"Error al calcular hashes del texto: {str(e)}")

    @staticmethod
    def calculate_file_hash(file_path, callback=None):
        #Calcula los hashes de un archivo.
        try:
            hash_objects = {
                'md5': hashlib.md5(),
                'sha1': hashlib.sha1(),
                'sha224': hashlib.sha224(),
                'sha256': hashlib.sha256(),
                'sha384': hashlib.sha384(),
                'sha512': hashlib.sha512(),
                'blake2b': blake2b(),
                'blake2s': blake2s()
            }

            with open(file_path, 'rb') as file:
                while chunk := file.read(8192):
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
                    if callback:
                        callback()

            return {name: hash_obj.hexdigest() 
                   for name, hash_obj in hash_objects.items()}
        except Exception as e:
            raise Exception(f"Error al procesar el archivo: {str(e)}")


    @staticmethod
    def compare_files(file_path1, file_path2):
        #Compara los hashes de dos archivos.
        try:
            # Calcular hashes para ambos archivos
            hashes1 = HashLogica.calculate_file_hash(file_path1)
            hashes2 = HashLogica.calculate_file_hash(file_path2)

            # Comparar los hashes y preparar resultados
            results = {
                'match': all(hashes1[algo] == hashes2[algo] for algo in hashes1.keys()),
                'hashes1': hashes1,
                'hashes2': hashes2,
                'comparisons': {}
            }

            # Agregar comparaciones detalladas por algoritmo
            for algo in hashes1.keys():
                results['comparisons'][algo] = {
                    'match': hashes1[algo] == hashes2[algo],
                    'hash1': hashes1[algo],
                    'hash2': hashes2[algo]
                }

            return results
        except Exception as e:
            raise Exception(f"Error al comparar archivos: {str(e)}")