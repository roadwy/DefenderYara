
rule Trojan_Win32_Cridex_FR_MTB{
	meta:
		description = "Trojan:Win32/Cridex.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b f0 89 44 24 1c 8b 44 24 24 83 ee 4d 05 ?? ?? ?? ?? 8b fe 89 01 33 c9 89 44 24 24 a3 50 1b 06 10 0f b6 05 ?? ?? ?? ?? 2b 44 24 0c 3d ?? ?? ?? ?? 75 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}