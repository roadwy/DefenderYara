
rule Ransom_Win64_Filecoder_GA_MTB{
	meta:
		description = "Ransom:Win64/Filecoder.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 54 45 4d 50 5c 72 61 6e 73 6f 6d 62 65 61 72 2e 65 78 65 } //01 00  C:\TEMP\ransombear.exe
		$a_01_1 = {43 3a 5c 54 45 4d 50 5c 4c 61 75 6e 63 68 52 61 6e 73 6f 6d 62 65 61 72 2e 64 6c 6c } //01 00  C:\TEMP\LaunchRansombear.dll
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 2e 65 78 65 20 2f 63 20 43 3a 5c 72 61 6e 73 6f 6d 62 65 61 72 2e 65 78 65 } //00 00  C:\WINDOWS\system32\cmd.exe /c C:\ransombear.exe
	condition:
		any of ($a_*)
 
}