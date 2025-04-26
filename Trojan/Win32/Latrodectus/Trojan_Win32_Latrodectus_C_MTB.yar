
rule Trojan_Win32_Latrodectus_C_MTB{
	meta:
		description = "Trojan:Win32/Latrodectus.C!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 d8 41 8b c0 f7 e9 d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 f7 ea d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 f7 ea d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c0 f7 ea 41 8b c0 d1 fa 8b ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}