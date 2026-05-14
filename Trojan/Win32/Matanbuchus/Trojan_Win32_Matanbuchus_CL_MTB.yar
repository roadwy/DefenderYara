
rule Trojan_Win32_Matanbuchus_CL_MTB{
	meta:
		description = "Trojan:Win32/Matanbuchus.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 02 89 45 ?? 8b 4a ?? 89 4d ?? 8b 52 ?? 89 55 ?? 8b 45 ?? 50 8b 4d ?? 8b 11 81 c2 ?? ?? ?? ?? 52 8b 45 ?? 8b 48 ?? 51 6a 00 8d 55 ?? 52 8d 45 ?? 50 e8 } //5
		$a_01_1 = {55 89 e5 6a 33 e8 00 00 00 00 83 04 24 05 cb } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}