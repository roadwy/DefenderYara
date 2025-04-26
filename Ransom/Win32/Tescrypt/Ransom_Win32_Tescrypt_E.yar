
rule Ransom_Win32_Tescrypt_E{
	meta:
		description = "Ransom:Win32/Tescrypt.E,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {52 ff d7 83 c4 08 85 c0 74 16 68 42 a8 6f 9e 6a 01 6a 00 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 56 ff d0 90 09 05 00 68 } //1
		$a_01_1 = {5c 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 66 00 69 00 6c 00 65 00 5f 00 } //1 \recover_file_
		$a_01_2 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 62 6f 6f 74 73 74 61 74 75 73 70 6f 6c 69 63 79 20 49 67 6e 6f 72 65 41 6c 6c 46 61 69 6c 75 72 65 73 } //1 bcdedit.exe /set {current} bootstatuspolicy IgnoreAllFailures
		$a_01_3 = {62 63 64 65 64 69 74 2e 65 78 65 20 2f 73 65 74 20 7b 63 75 72 72 65 6e 74 7d 20 72 65 63 6f 76 65 72 79 65 6e 61 62 6c 65 64 20 6f 66 66 } //1 bcdedit.exe /set {current} recoveryenabled off
		$a_00_4 = {68 00 65 00 6c 00 70 00 5f 00 72 00 65 00 63 00 6f 00 76 00 65 00 72 00 5f 00 69 00 6e 00 73 00 74 00 72 00 75 00 63 00 74 00 69 00 6f 00 6e 00 73 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}