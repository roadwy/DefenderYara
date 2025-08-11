
rule Trojan_Win32_BadJoke_KAB_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.KAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {ba 81 80 80 80 89 c8 f7 ea 8d 04 0a c1 f8 07 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 08 29 d0 29 c1 89 ca 89 d0 0f b6 c0 c1 e0 10 80 cc ff } //20
		$a_01_1 = {ba c5 b3 a2 91 89 c8 f7 ea 8d 04 0a 89 c2 c1 fa 0b 89 cb c1 fb 1f 89 d8 89 d7 29 c7 69 c7 10 0e 00 00 89 cf 29 c7 } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}