
rule Trojan_Win32_ShadowPad_B_MTB{
	meta:
		description = "Trojan:Win32/ShadowPad.B!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {19 51 00 00 0f 85 b0 0e 00 00 e8 60 29 00 00 3c 01 } //1
		$a_01_1 = {48 55 8b ec 8b 45 08 e8 b2 29 00 00 57 67 00 00 14 5f e8 a7 29 00 00 92 69 00 00 43 e8 6a 4e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}