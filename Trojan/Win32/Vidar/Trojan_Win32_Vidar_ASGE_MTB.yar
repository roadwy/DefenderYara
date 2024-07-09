
rule Trojan_Win32_Vidar_ASGE_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASGE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d4 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 c0 04 01 45 d4 8b 45 ec 3b 45 d0 72 } //2
		$a_03_1 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 89 45 ?? c7 45 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}