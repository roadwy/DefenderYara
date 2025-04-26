
rule Trojan_Win32_ShadowPad_C_MTB{
	meta:
		description = "Trojan:Win32/ShadowPad.C!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 5d e8 c7 45 ec 56 69 72 74 c7 45 f0 75 61 6c 50 c7 45 f4 72 6f 74 65 66 c7 45 f8 63 74 c6 45 fa 00 } //1
		$a_01_1 = {8b f9 8b f2 8b 5d 08 33 c0 40 89 45 e4 85 f6 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}