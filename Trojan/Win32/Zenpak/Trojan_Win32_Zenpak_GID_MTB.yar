
rule Trojan_Win32_Zenpak_GID_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 f2 05 01 25 90 01 04 83 ea 07 e8 90 01 04 29 d0 29 d0 89 2d 90 01 04 83 e8 0a 8d 05 90 01 04 31 38 8d 05 90 01 04 89 30 48 40 83 c2 03 89 d8 50 8f 05 90 01 04 8d 05 90 01 04 ff d0 b9 02 00 00 00 e2 c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}