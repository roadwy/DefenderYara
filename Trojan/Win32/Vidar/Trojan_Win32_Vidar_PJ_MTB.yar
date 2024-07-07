
rule Trojan_Win32_Vidar_PJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 90 01 08 89 45 08 8b 45 e4 01 45 08 03 f3 33 75 08 8d 45 f4 33 75 0c 56 50 90 00 } //1
		$a_01_1 = {55 8b ec 8b 45 08 8b 4d 0c 29 08 5d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}