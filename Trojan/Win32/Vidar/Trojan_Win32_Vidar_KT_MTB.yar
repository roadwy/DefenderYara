
rule Trojan_Win32_Vidar_KT_MTB{
	meta:
		description = "Trojan:Win32/Vidar.KT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 a8 05 ?? ?? ?? ?? 2b 45 a0 03 d8 } //1
		$a_01_1 = {2b d8 8b 45 d8 31 18 } //1
		$a_01_2 = {83 45 d8 04 8b 45 ec 3b 45 d4 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}