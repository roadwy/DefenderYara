
rule Trojan_Win32_DanaBot_GB_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {30 04 37 4e } //01 00  а丷
		$a_02_1 = {8a 18 88 10 88 19 0f b6 00 0f b6 cb 03 c1 90 02 30 23 c6 8a 80 90 02 25 33 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}