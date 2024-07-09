
rule Trojan_Win64_Havoc_YAT_MTB{
	meta:
		description = "Trojan:Win64/Havoc.YAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 4f 60 41 33 cb 01 4f ?? 48 8b 05 ?? ?? ?? ?? 8b 08 01 0d ?? ?? ?? ?? 48 63 0d ?? ?? ?? ?? 48 8b 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}