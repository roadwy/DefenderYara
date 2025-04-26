
rule Trojan_Win64_Lazy_GD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {4c 8b 84 24 ?? ?? ?? ?? 8a 11 4d 8b 00 41 32 54 00 08 88 11 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}