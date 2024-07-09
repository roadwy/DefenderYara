
rule Trojan_Win32_Vidar_PAK_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 d3 ea 03 45 ?? 89 45 ?? 8b 45 e4 03 55 cc 03 c7 89 45 f0 8b 45 f0 31 45 fc 31 55 fc 89 35 ?? ?? ?? ?? 8b 45 f8 89 45 e8 8b 45 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}