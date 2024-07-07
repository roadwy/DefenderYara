
rule Trojan_Win32_Vidar_DA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d8 8b 1a 03 5d ec 2b d8 6a 66 e8 90 01 04 03 d8 8b 45 d8 89 18 8b 45 c8 03 45 a0 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}