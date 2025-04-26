
rule Ransom_MSIL_LokiLocker_ZB_MTB{
	meta:
		description = "Ransom:MSIL/LokiLocker.ZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 22 00 0b 00 00 "
		
	strings :
		$a_01_0 = {73 76 63 68 6f 73 74 2e 65 78 65 } //10 svchost.exe
		$a_01_1 = {4c 6f 6b 69 2e 50 69 6e 76 6f 6b 65 2e 4e 61 74 69 76 65 2e 49 50 5f 41 44 41 50 54 45 52 5f 49 4e 46 4f } //10 Loki.Pinvoke.Native.IP_ADAPTER_INFO
		$a_01_2 = {42 43 72 79 70 74 45 6e 63 72 79 70 74 } //10 BCryptEncrypt
		$a_01_3 = {53 74 72 65 61 6d 57 72 69 74 65 72 } //1 StreamWriter
		$a_01_4 = {42 69 6e 61 72 79 57 72 69 74 65 72 } //1 BinaryWriter
		$a_01_5 = {43 72 65 61 74 65 45 6e 63 72 79 70 74 6f 72 } //1 CreateEncryptor
		$a_01_6 = {4c 6f 6b 69 2e 49 4f 2e 41 6c 67 6f 72 69 74 68 6d 73 2e 5a 69 70 2e 46 69 6c 65 49 6e 66 6f 2e 5a 69 70 46 69 6c 65 49 6e 66 6f } //1 Loki.IO.Algorithms.Zip.FileInfo.ZipFileInfo
		$a_01_7 = {53 48 45 6d 70 74 79 52 65 63 79 63 6c 65 42 69 6e } //1 SHEmptyRecycleBin
		$a_01_8 = {65 6e 63 72 79 70 74 65 64 50 72 69 76 61 74 65 4b 65 79 } //1 encryptedPrivateKey
		$a_01_9 = {67 65 74 5f 49 73 36 34 42 69 74 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //1 get_Is64BitOperatingSystem
		$a_01_10 = {3c 4c 6f 6b 69 3e } //1 <Loki>
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=34
 
}