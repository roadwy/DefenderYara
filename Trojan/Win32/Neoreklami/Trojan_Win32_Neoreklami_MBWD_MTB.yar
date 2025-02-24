
rule Trojan_Win32_Neoreklami_MBWD_MTB{
	meta:
		description = "Trojan:Win32/Neoreklami.MBWD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {e9 5f 61 04 00 af 52 1e 7a 57 cd 73 1e a6 63 36 66 f4 29 4a b9 e9 62 35 13 3a 65 5e b9 09 b5 e1 34 3c 01 2b 4f 8b 90 de b8 e8 28 ea 92 d9 cc } //2
		$a_01_1 = {2c da 16 96 f8 f2 c1 41 16 59 aa ed 88 36 b1 b0 c9 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}