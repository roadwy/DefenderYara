
rule Ransom_MSIL_Filecoder_ARAF_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {5c 73 74 61 72 74 52 61 6e 73 2e 62 61 74 } //02 00  \startRans.bat
		$a_01_1 = {5c 72 65 63 6f 76 65 72 79 4b 65 79 2e 74 78 74 } //02 00  \recoveryKey.txt
		$a_01_2 = {5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 73 74 61 72 74 56 73 2e 62 61 74 } //02 00  \Programs\Startup\startVs.bat
		$a_01_3 = {5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 73 68 75 74 64 6f 77 6e 20 2f 72 20 2f 74 20 30 } //00 00  \windows\system32\shutdown /r /t 0
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Filecoder_ARAF_MTB_2{
	meta:
		description = "Ransom:MSIL/Filecoder.ARAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {08 09 9a 13 04 00 11 04 6f 90 01 03 0a 6f 90 01 03 0a 72 81 01 00 70 28 90 01 03 0a 13 05 11 05 2c 3d 00 72 8b 01 00 70 13 06 11 04 6f 90 01 03 0a 11 04 6f 90 01 03 0a 72 9d 01 00 70 28 90 01 03 0a 11 06 28 90 01 03 06 00 11 04 6f 90 01 03 0a 28 90 01 03 0a 00 03 28 90 01 03 0a 00 00 00 09 17 58 0d 09 08 8e 69 32 96 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}