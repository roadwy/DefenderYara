
rule Ransom_Win64_Tuga_GDR_MTB{
	meta:
		description = "Ransom:Win64/Tuga.GDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 78 36 34 2f 52 65 6c 65 61 73 65 2f 44 61 74 61 44 65 63 72 79 70 74 6f 72 2e 65 78 65 } //01 00  /x64/Release/DataDecryptor.exe
		$a_01_1 = {78 36 34 2f 52 65 6c 65 61 73 65 2f 64 65 62 75 67 46 6f 6c 64 65 72 5f 62 61 63 6b 75 70 2f 70 64 66 73 61 6d 70 6c 65 2e 70 64 66 } //01 00  x64/Release/debugFolder_backup/pdfsample.pdf
		$a_01_2 = {2e 2f 65 6d 61 69 6c 53 65 6e 64 65 72 2e 70 73 31 } //00 00  ./emailSender.ps1
	condition:
		any of ($a_*)
 
}