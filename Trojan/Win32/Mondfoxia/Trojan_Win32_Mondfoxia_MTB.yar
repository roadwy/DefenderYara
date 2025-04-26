
rule Trojan_Win32_Mondfoxia_MTB{
	meta:
		description = "Trojan:Win32/Mondfoxia!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 8d 34 03 e8 ?? ?? ?? ?? 30 06 b8 ?? ?? ?? ?? 29 45 ?? 39 7d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Mondfoxia_MTB_2{
	meta:
		description = "Trojan:Win32/Mondfoxia!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 34 18 e8 ?? ?? ?? ?? 30 06 b8 ?? ?? ?? ?? 29 85 ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 85 c0 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}