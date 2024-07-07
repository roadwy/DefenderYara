
rule Trojan_Win32_SpyStealer_AS_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 02 8b 45 90 01 01 03 45 90 01 01 03 45 90 01 01 03 45 90 01 01 89 45 90 00 } //1
		$a_03_1 = {2b d8 8b 45 90 01 01 31 18 83 45 90 01 02 83 45 90 01 02 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}