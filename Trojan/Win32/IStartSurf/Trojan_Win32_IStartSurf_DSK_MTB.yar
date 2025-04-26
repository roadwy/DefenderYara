
rule Trojan_Win32_IStartSurf_DSK_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 06 8b c6 f7 75 d0 8b 45 14 88 4d ff 8a 04 02 32 c1 8b 4d 10 88 04 0e } //2
		$a_01_1 = {8b 45 dc 83 c0 12 50 ff 75 d4 8b 45 dc ff 70 04 8b 45 dc 8b 4d d8 03 08 51 e8 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}