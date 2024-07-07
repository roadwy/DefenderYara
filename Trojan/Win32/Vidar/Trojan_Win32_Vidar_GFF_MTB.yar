
rule Trojan_Win32_Vidar_GFF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c1 0f af c3 99 89 44 24 18 8b 44 24 68 89 54 24 1c 28 44 24 13 0f b6 44 24 15 0f af 44 24 3c 0f af 44 24 3c 89 44 24 3c 8b 44 24 18 a3 90 01 04 8b 44 24 1c a3 90 01 04 a0 90 01 04 04 90 01 01 30 44 24 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}