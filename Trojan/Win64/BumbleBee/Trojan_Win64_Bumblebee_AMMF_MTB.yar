
rule Trojan_Win64_Bumblebee_AMMF_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 81 33 c2 48 63 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 48 8b 92 ?? ?? ?? ?? 89 04 8a 48 8b 84 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}