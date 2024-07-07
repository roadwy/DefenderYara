
rule Trojan_Win32_Vidar_C_MTB{
	meta:
		description = "Trojan:Win32/Vidar.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 54 24 12 0f b6 51 90 01 01 88 54 24 13 8a 51 90 01 01 89 5c 24 14 83 44 24 14 90 01 01 89 5c 24 18 83 44 24 18 90 01 01 8b 4c 24 14 8a da d2 e3 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}