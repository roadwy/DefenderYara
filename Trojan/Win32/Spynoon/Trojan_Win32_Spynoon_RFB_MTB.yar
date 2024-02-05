
rule Trojan_Win32_Spynoon_RFB_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RFB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {b8 cd cc cc cc f7 e6 8b c6 c1 ea 03 68 90 01 04 8d 0c 92 03 c9 2b c1 8a 80 90 01 04 30 04 3e e8 90 01 04 46 83 c4 04 3b f3 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}