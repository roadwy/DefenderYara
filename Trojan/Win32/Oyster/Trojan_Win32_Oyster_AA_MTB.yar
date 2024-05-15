
rule Trojan_Win32_Oyster_AA_MTB{
	meta:
		description = "Trojan:Win32/Oyster.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 c7 45 fc 90 01 04 8b c6 8d 0c 1e f7 75 fc 2b 55 f8 8a 44 15 90 01 01 32 04 39 46 88 01 81 fe 90 01 04 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}