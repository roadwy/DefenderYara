
rule Trojan_Win32_Zenpack_EG_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {83 ea 05 89 e8 50 8f 05 90 01 04 e9 90 01 04 c3 8d 05 90 01 04 31 18 01 d0 31 c2 89 f0 50 8f 05 90 01 04 31 3d 90 01 04 eb d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}