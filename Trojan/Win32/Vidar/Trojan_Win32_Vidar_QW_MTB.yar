
rule Trojan_Win32_Vidar_QW_MTB{
	meta:
		description = "Trojan:Win32/Vidar.QW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 55 a8 81 c2 ?? ?? ?? ?? 2b 55 a0 2b d0 8b 45 d8 31 10 6a 00 } //1
		$a_01_1 = {83 45 d8 04 8b 45 ec 3b 45 d4 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}