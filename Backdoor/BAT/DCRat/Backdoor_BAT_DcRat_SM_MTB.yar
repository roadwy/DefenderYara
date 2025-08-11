
rule Backdoor_BAT_DcRat_SM_MTB{
	meta:
		description = "Backdoor:BAT/DcRat.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 09 58 91 02 7b 0b 00 00 04 09 91 fe 01 13 05 11 05 2d 05 00 16 0c 2b 16 00 09 17 58 0d 09 02 7b 0b 00 00 04 8e 69 fe 04 13 05 11 05 2d cf } //2
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 } //2 Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
		$a_81_2 = {53 68 6f 77 53 75 70 65 72 48 69 64 64 65 6e } //2 ShowSuperHidden
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}