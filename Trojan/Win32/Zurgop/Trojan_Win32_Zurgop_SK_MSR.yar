
rule Trojan_Win32_Zurgop_SK_MSR{
	meta:
		description = "Trojan:Win32/Zurgop.SK!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 84 24 9c 02 00 00 8a 94 06 3b 2d 0b 00 88 14 01 5e 81 c4 94 02 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}