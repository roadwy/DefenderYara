
rule Backdoor_BAT_XWorm_PAFT_MTB{
	meta:
		description = "Backdoor:BAT/XWorm.PAFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 00 77 00 6f 00 72 00 6d 00 73 00 5c 00 2e 00 } //2 \worms\.
		$a_00_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //1 SELECT * FROM AntiVirusProduct
		$a_00_2 = {4e 00 6f 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 } //1 No Antivirus
		$a_00_3 = {42 00 6c 00 61 00 63 00 6b 00 20 00 48 00 61 00 74 00 20 00 57 00 6f 00 72 00 6d 00 } //2 Black Hat Worm
		$a_01_4 = {53 45 54 44 45 53 4b 57 41 4c 4c 50 41 50 45 52 } //2 SETDESKWALLPAPER
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*2+(#a_01_4  & 1)*2) >=8
 
}