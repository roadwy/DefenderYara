
rule Trojan_Win32_GandCrypt_PVI_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.PVI!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d6 c1 ea 05 03 54 24 10 8b c6 c1 e0 04 03 44 24 14 8d 0c 33 33 d0 33 d1 2b fa 81 fd 8b 02 00 00 73 } //2
		$a_01_1 = {8b 55 f4 c1 ea 05 03 55 e0 33 c2 8b 4d dc 2b c8 89 4d dc 81 7d fc c5 22 00 00 73 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}