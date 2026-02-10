import hashlib
import os
import zlib

class HashLogica:
    @staticmethod
    def verify_file_integrity(file_path, expected_hash):
        """Verifica si el hash esperado coincide con alguno de los hashes calculados del archivo."""
        try:
            calculated_hashes = HashLogica.calculate_file_hash(file_path)
            expected_hash = expected_hash.lower().strip()
            
            for algo, val in calculated_hashes.items():
                if val == expected_hash:
                    return {
                        'match': True,
                        'algorithm': algo,
                        'calculated_hash': val
                    }
            
            # Si no coincide con ninguno, devolvemos el sha256 como referencia o el primero
            return {
                'match': False,
                'algorithm': 'sha256',
                'calculated_hash': calculated_hashes.get('sha256', list(calculated_hashes.values())[0])
            }
        except Exception as e:
            raise Exception(f"Error al verificar integridad: {str(e)}")

    @staticmethod
    def calculate_hashes(texto):
        #Calcula los hashes de un texto.
        try:
            encoded_text = texto.encode('utf-8')
            hashes = {
                'md5': hashlib.md5(encoded_text).hexdigest(),
                'sha1': hashlib.sha1(encoded_text).hexdigest(),
                'sha224': hashlib.sha224(encoded_text).hexdigest(),
                'sha256': hashlib.sha256(encoded_text).hexdigest(),
                'sha384': hashlib.sha384(encoded_text).hexdigest(),
                'sha512': hashlib.sha512(encoded_text).hexdigest(),
                'blake2b': hashlib.blake2b(encoded_text).hexdigest(),
                'blake2s': hashlib.blake2s(encoded_text).hexdigest()
            }
            if hasattr(hashlib, 'sha3_256'):
                hashes['sha3_256'] = hashlib.sha3_256(encoded_text).hexdigest()
                hashes['sha3_512'] = hashlib.sha3_512(encoded_text).hexdigest()
            hashes['crc32'] = format(zlib.crc32(encoded_text) & 0xFFFFFFFF, '08x')
            return hashes
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
                'blake2b': hashlib.blake2b(),
                'blake2s': hashlib.blake2s()
            }
            if hasattr(hashlib, 'sha3_256'):
                hash_objects['sha3_256'] = hashlib.sha3_256()
                hash_objects['sha3_512'] = hashlib.sha3_512()
            crc_val = 0
            with open(file_path, 'rb') as file:
                total_size = os.path.getsize(file_path)
                read_size = 0
                while chunk := file.read(8192):
                    read_size += len(chunk)
                    for hash_obj in hash_objects.values():
                        hash_obj.update(chunk)
                    crc_val = zlib.crc32(chunk, crc_val)
                    if callback:
                        callback(int(read_size / total_size * 100))
            result = {name: hash_obj.hexdigest() for name, hash_obj in hash_objects.items()}
            result['crc32'] = format(crc_val & 0xFFFFFFFF, '08x')
            return result
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