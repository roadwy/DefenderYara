
rule Trojan_Win32_Pony_AM_MTB{
	meta:
		description = "Trojan:Win32/Pony.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {35 f8 26 4f bf 99 fd fd 46 b2 33 c9 2a e0 27 30 4e 3c 56 44 8d 83 3c ec 53 e4 2d 05 0f 5c f3 19 c5 c1 d6 41 b7 c1 11 0a a6 fb f0 7b } //1
		$a_01_1 = {2b 33 71 b5 05 80 c1 82 80 89 9f 4c 8a fd 1e 4b f7 6c 51 10 21 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}