
rule Trojan_Win32_Fragtor_GPC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 67 66 66 66 f7 ea c1 fa 02 8b c2 c1 e8 1f 03 c2 8b 55 fc 8a c8 c0 e0 02 02 c8 8a c2 02 c9 2a c1 04 30 30 44 15 f0 42 89 55 fc } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}