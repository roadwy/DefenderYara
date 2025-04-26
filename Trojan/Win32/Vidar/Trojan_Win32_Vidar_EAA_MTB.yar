
rule Trojan_Win32_Vidar_EAA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.EAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 4c 24 07 00 c8 00 44 24 07 0f b6 44 24 08 0f b6 c0 89 c1 c1 e1 04 01 c1 f7 d9 00 4c 24 08 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}