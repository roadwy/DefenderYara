
rule Trojan_Win32_Vidar_BKL_MTB{
	meta:
		description = "Trojan:Win32/Vidar.BKL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 4c 24 1c 8b c6 c1 e8 05 03 44 24 24 c7 05 40 1b 2d 02 00 00 00 00 33 c1 8d 0c 33 33 c1 2b f8 8b d7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}