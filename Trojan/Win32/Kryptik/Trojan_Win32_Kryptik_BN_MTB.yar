
rule Trojan_Win32_Kryptik_BN_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {c7 44 24 20 00 00 00 00 81 6c 24 20 aa a0 5b 7e 81 44 24 20 62 7e e6 6f 81 44 24 20 4d 22 75 0e 8b 4c 24 20 8b d0 d3 ea 03 c7 03 54 24 40 33 d0 33 d6 2b ea 81 3d 90 01 04 fd 13 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}