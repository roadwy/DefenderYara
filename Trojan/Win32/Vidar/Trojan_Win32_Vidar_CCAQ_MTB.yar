
rule Trojan_Win32_Vidar_CCAQ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CCAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 d3 ef 89 45 e0 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 7d e4 8b 45 e0 31 45 fc 33 7d fc 81 3d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}