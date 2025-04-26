
rule Trojan_Win32_Vidar_TWZ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.TWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d 38 ?? ?? ?? 8a 15 ?? ?? ?? ?? 8b 4c 24 14 30 14 0e 83 f8 0f 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}