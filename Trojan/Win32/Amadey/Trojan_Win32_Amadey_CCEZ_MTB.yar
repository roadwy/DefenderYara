
rule Trojan_Win32_Amadey_CCEZ_MTB{
	meta:
		description = "Trojan:Win32/Amadey.CCEZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 81 c3 ?? ?? ?? ?? 8b 45 ?? 31 18 83 45 ?? ?? 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}