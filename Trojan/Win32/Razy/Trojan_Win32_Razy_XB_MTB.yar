
rule Trojan_Win32_Razy_XB_MTB{
	meta:
		description = "Trojan:Win32/Razy.XB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {c1 24 15 27 16 39 f6 74 01 ea 31 33 4a 81 c0 90 01 04 81 c3 90 01 04 39 fb 75 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}