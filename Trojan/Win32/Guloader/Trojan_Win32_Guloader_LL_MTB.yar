
rule Trojan_Win32_Guloader_LL_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 52 f4 66 3d 74 75 81 fa 2b 9d 52 0d 81 fb f8 6f e8 3e 31 34 24 85 d2 66 85 c0 81 fa c3 89 ef df 66 3d b3 d1 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}