
rule Trojan_Win32_Vidar_TEH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.TEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 fa 83 e2 03 8a 54 14 38 30 14 38 47 8b 44 24 04 8b 54 24 08 89 d6 29 c6 39 f7 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}