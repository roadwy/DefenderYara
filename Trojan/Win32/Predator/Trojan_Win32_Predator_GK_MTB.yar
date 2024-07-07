
rule Trojan_Win32_Predator_GK_MTB{
	meta:
		description = "Trojan:Win32/Predator.GK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 dc 0f b6 82 98 b0 44 00 89 45 e0 8b 4d e0 f7 d1 89 4d e0 8b 55 e0 2b 55 dc 89 55 e0 } //1
		$a_01_1 = {8b 4d e0 03 4d dc 89 4d e0 8b 55 e0 f7 d2 89 55 e0 8b 45 e0 35 90 01 01 00 00 00 89 45 e0 8b 4d dc 8a 55 e0 88 91 90 01 03 00 e9 9a fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}