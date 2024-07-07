
rule Trojan_BAT_Lazy_ARA_MTB{
	meta:
		description = "Trojan:BAT/Lazy.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 2a 02 07 6f 90 01 03 0a 03 07 03 6f 90 01 03 0a 5d 6f 90 01 03 0a 0c 08 61 d1 0d 06 09 6f 90 01 03 0a 26 07 28 90 01 03 06 58 0b 07 02 6f 90 01 03 0a 32 cd 90 00 } //2
		$a_80_1 = {5c 74 65 6d 70 2e 70 73 31 } //\temp.ps1  2
		$a_80_2 = {5c 74 65 6d 70 2e 62 61 74 } //\temp.bat  2
	condition:
		((#a_03_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=6
 
}