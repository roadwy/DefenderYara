
rule Trojan_Win32_Blocker_BE_MTB{
	meta:
		description = "Trojan:Win32/Blocker.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 99 66 cf 11 b7 0c 00 aa 00 60 d3 93 46 69 6c 65 31 00 00 00 2e 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 43 3a 5c 50 72 6f 67 72 } //2
		$a_01_1 = {35 34 ff 00 10 6c 10 00 04 34 ff 0a 1a 00 08 00 35 34 ff 00 00 fd 95 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}