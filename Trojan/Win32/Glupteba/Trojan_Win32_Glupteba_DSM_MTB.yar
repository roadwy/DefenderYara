
rule Trojan_Win32_Glupteba_DSM_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 24 8b f3 c1 ee 05 03 74 24 20 03 f9 8d 14 2b 33 fa 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } //1
		$a_01_1 = {8b 84 24 34 04 00 00 8b 54 24 08 5d 89 18 89 50 04 5b 81 c4 28 04 00 00 c2 04 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}