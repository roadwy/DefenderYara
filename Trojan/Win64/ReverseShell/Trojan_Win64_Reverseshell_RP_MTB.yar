
rule Trojan_Win64_Reverseshell_RP_MTB{
	meta:
		description = "Trojan:Win64/Reverseshell.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 00 00 48 8b 05 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 8b 05 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 8b 05 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 8b 05 ?? ?? 00 00 48 89 85 ?? ?? 00 00 48 b8 63 6d 64 2e 65 78 65 00 48 89 85 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}