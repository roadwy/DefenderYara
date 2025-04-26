
rule Ransom_MSIL_Filecoder_AN_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 50 00 65 00 6e 00 74 00 65 00 72 00 57 00 61 00 72 00 65 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 6f 00 72 00 2e 00 74 00 78 00 74 00 } //1 ProgramData\PenterWareDecryptor.txt
		$a_01_1 = {65 00 63 00 68 00 6f 00 20 00 6a 00 20 00 7c 00 20 00 64 00 65 00 6c 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 4d 00 79 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 2e 00 62 00 61 00 74 00 } //1 echo j | del deleteMyProgram.bat
		$a_01_2 = {48 4b 4c 4d 5c 53 4f 46 54 57 41 52 45 5c 72 65 63 66 67 5c 73 6b 5f 6b 65 79 } //1 HKLM\SOFTWARE\recfg\sk_key
		$a_01_3 = {79 6e 65 74 2e 63 6f 2e 69 6c } //1 ynet.co.il
		$a_01_4 = {64 00 65 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 4b 00 65 00 79 00 } //1 decryptionKey
		$a_01_5 = {66 00 69 00 6c 00 65 00 73 00 54 00 6f 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 } //1 filesToDecrypt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}