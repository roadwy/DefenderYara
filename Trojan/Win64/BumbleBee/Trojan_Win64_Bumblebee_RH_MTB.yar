
rule Trojan_Win64_Bumblebee_RH_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 0b ca 48 0f af c1 48 89 42 ?? 49 63 96 ?? ?? ?? ?? 49 8b 0e 49 8b 46 ?? 8a 14 0a 41 32 14 00 49 8b 46 ?? 41 88 14 00 49 ff c0 49 8b 86 ?? ?? ?? ?? 49 8b 8e ?? ?? ?? ?? 49 0b cb 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}