
rule Trojan_Win32_SpyStealer_AS_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 ?? 03 45 ?? 03 45 ?? 03 45 ?? 89 45 } //1
		$a_03_1 = {2b d8 8b 45 ?? 31 18 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}