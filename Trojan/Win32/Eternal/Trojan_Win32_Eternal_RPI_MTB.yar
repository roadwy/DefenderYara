
rule Trojan_Win32_Eternal_RPI_MTB{
	meta:
		description = "Trojan:Win32/Eternal.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 61 75 6d 31 38 31 30 } //01 00  baum1810
		$a_01_1 = {3a 25 78 6a 46 4e 42 72 51 77 4d 25 3a } //01 00  :%xjFNBrQwM%:
		$a_01_2 = {3a 25 78 65 6c 4f 7a 53 59 25 3a } //01 00  :%xelOzSY%:
		$a_01_3 = {3a 25 4c 6f 6c 76 25 3a } //01 00  :%Lolv%:
		$a_01_4 = {3a 25 48 53 55 4c 49 78 56 4c 6c 25 3a } //01 00  :%HSULIxVLl%:
		$a_01_5 = {3a 25 4a 5a 64 41 6e 48 51 58 6a 66 25 3a } //00 00  :%JZdAnHQXjf%:
	condition:
		any of ($a_*)
 
}