
rule Trojan_Win32_Tedy_MBJV_MTB{
	meta:
		description = "Trojan:Win32/Tedy.MBJV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 c4 33 c9 85 c0 0f 95 c1 f7 d9 66 85 c9 74 2f 8d 45 c8 8d 4d d8 8d 55 ec 50 51 } //1
		$a_01_1 = {80 08 4a 00 e0 23 40 00 5f f8 b0 00 00 ff ff ff 08 00 00 00 01 00 00 00 02 00 04 00 e9 00 00 00 58 21 40 00 c4 2f 40 00 f0 1f 40 00 78 00 00 00 87 00 00 00 96 00 00 00 97 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}