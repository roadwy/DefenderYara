
rule Trojan_Win32_NSISInject_RPV_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {53 63 72 75 6d 70 74 69 6f 6e } //01 00  Scrumption
		$a_81_1 = {45 6c 6c 69 70 73 6f 69 64 65 72 6e 65 31 31 34 2e 42 79 64 } //01 00  Ellipsoiderne114.Byd
		$a_81_2 = {45 6e 6b 65 6c 74 68 65 64 65 72 2e 69 6e 69 } //01 00  Enkeltheder.ini
		$a_81_3 = {55 67 65 6e 6e 65 6d 66 72 6c 69 67 68 65 64 65 6e 73 32 34 36 2e 6c 6e 6b } //01 00  Ugennemfrlighedens246.lnk
		$a_81_4 = {4e 6f 63 74 61 6d 62 75 6c 69 73 74 69 63 2e 50 61 6c } //00 00  Noctambulistic.Pal
	condition:
		any of ($a_*)
 
}