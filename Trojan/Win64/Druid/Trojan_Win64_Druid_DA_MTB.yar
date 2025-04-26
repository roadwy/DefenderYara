
rule Trojan_Win64_Druid_DA_MTB{
	meta:
		description = "Trojan:Win64/Druid.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 08 48 3b c1 73 ?? 48 63 04 24 48 8b 4c 24 30 0f be 04 01 0f be 0d ?? ?? ?? ?? 33 c1 48 63 0c 24 48 8b 54 24 30 88 04 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}