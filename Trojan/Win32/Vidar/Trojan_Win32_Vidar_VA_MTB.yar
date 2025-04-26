
rule Trojan_Win32_Vidar_VA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.VA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 c1 ea 05 03 54 24 1c 8b f8 c1 e7 04 03 7c 24 20 03 c1 33 d7 33 d0 2b f2 8b d6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}