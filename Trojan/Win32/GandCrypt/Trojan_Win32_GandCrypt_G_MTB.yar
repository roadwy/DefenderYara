
rule Trojan_Win32_GandCrypt_G_MTB{
	meta:
		description = "Trojan:Win32/GandCrypt.G!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8a 94 01 32 09 00 00 8b 4d 08 88 14 01 5d } //1
		$a_01_1 = {8d 9b 00 00 00 00 8b 7d fc 8a 44 37 03 8a d0 8a d8 80 e2 fc 24 f0 c0 e2 04 0a 54 37 01 8b 7d fc 02 c0 c0 e3 06 0a 5c 37 02 02 c0 0a 04 37 8b 7d f8 88 04 39 41 88 14 39 41 88 1c 39 83 c6 04 41 3b 75 f4 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}