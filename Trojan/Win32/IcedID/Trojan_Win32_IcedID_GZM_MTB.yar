
rule Trojan_Win32_IcedID_GZM_MTB{
	meta:
		description = "Trojan:Win32/IcedID.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {52 31 ff 2b 39 f7 df 83 c1 90 01 01 83 ef 90 01 01 31 c7 83 ef 90 01 01 31 c0 29 f8 f7 d8 89 3a 83 ea 90 01 01 83 c6 90 01 01 83 fe 90 01 01 75 dc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}