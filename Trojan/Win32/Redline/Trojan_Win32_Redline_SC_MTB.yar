
rule Trojan_Win32_Redline_SC_MTB{
	meta:
		description = "Trojan:Win32/Redline.SC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {e0 7f 56 00 c7 05 90 01 04 dc 7f 56 00 c7 05 90 01 04 d8 7f 56 00 c7 05 90 01 04 6c 00 00 00 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}