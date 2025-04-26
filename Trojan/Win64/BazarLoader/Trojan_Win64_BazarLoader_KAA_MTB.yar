
rule Trojan_Win64_BazarLoader_KAA_MTB{
	meta:
		description = "Trojan:Win64/BazarLoader.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {59 58 89 07 b8 ?? ?? ?? ?? 48 8d 7f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}