
rule Ransom_Win32_Filecoder_MA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c6 99 f7 f9 8a 44 15 ec 30 04 1e 46 3b f7 7c ef } //01 00 
		$a_01_1 = {6f 75 74 70 75 74 2e 74 78 74 } //01 00  output.txt
		$a_01_2 = {44 65 63 72 79 70 74 4d 65 73 73 61 67 65 } //01 00  DecryptMessage
		$a_01_3 = {3a 5c 57 69 6e 64 6f 77 73 5c 54 65 6d 70 5c 64 65 73 6b 74 6f 70 2e 6a 70 67 } //01 00  :\Windows\Temp\desktop.jpg
		$a_01_4 = {66 75 63 6b 6d 65 } //00 00  fuckme
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_Filecoder_MA_MTB_2{
	meta:
		description = "Ransom:Win32/Filecoder.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 33 89 7b 04 c6 05 59 50 4f 00 01 8b 45 08 50 8b 45 0c 50 53 b8 5c 9d 40 00 50 8b 45 f8 50 8b 45 fc 50 e8 e5 b3 ff ff } //01 00 
		$a_01_1 = {54 61 69 6c 50 72 6f 63 65 73 73 69 6e 67 41 6e 64 4b 65 79 47 65 6e 09 53 69 6d 70 6c 65 52 53 41 } //01 00 
		$a_01_2 = {4f 6e 65 50 61 74 68 45 6e 63 72 79 70 74 69 6f 6e 09 4c 61 6e 54 68 72 65 61 64 0b 4c 6f 63 61 6c 54 68 72 65 61 64 0d } //01 00 
		$a_01_3 = {46 69 6c 65 45 6e 63 72 79 70 74 69 6f 6e } //00 00  FileEncryption
	condition:
		any of ($a_*)
 
}