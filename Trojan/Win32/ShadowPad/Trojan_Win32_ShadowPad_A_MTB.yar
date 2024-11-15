
rule Trojan_Win32_ShadowPad_A_MTB{
	meta:
		description = "Trojan:Win32/ShadowPad.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 33 cf 7f a6 05 e2 a7 f7 b5 98 cc 48 42 1f cf 1e 2d 59 0a 62 b1 ed d6 64 } //1
		$a_01_1 = {83 60 03 00 80 60 1f 80 83 60 33 00 66 c7 40 ff 00 0a 66 c7 40 20 0a 0a c6 40 2f 00 8b 0f 83 c0 40 03 ce } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}