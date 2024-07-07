
rule Trojan_Win32_RootkitDrv_MP_MTB{
	meta:
		description = "Trojan:Win32/RootkitDrv.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 16 03 d1 33 c9 8a 02 84 c0 74 15 0f 1f 40 00 c1 c9 0d 8d 52 01 0f be c0 03 c8 8a 02 84 c0 75 ef 8b 45 fc 3b 4d f0 74 18 8b 4d f8 47 83 c6 04 83 c3 02 3b 78 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}