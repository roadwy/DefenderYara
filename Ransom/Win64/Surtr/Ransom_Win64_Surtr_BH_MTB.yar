
rule Ransom_Win64_Surtr_BH_MTB{
	meta:
		description = "Ransom:Win64/Surtr.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 5c 00 53 00 75 00 72 00 74 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  C:\ProgramData\Service\Surtr.exe
		$a_01_1 = {25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 20 00 4d 00 65 00 6e 00 75 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 53 00 75 00 72 00 74 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  %appdata%\Microsoft\Windows\Start Menu\Programs\Startup\Surtr.exe
		$a_01_2 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 53 65 72 76 69 63 65 5c 53 55 52 54 52 5f 52 45 41 44 4d 45 2e 74 78 74 } //00 00  C:\ProgramData\Service\SURTR_README.txt
	condition:
		any of ($a_*)
 
}