
rule Trojan_Win32_Vidar_ASGD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 ?? 31 10 83 45 ?? 04 6a 00 e8 ?? ?? ?? ff 83 c0 04 01 45 ?? 8b 45 ?? 3b 45 ?? 72 } //2
		$a_03_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}