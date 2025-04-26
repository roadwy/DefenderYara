
rule Trojan_Win64_Luca_GZT_MTB{
	meta:
		description = "Trojan:Win64/Luca.GZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 08 48 ba ?? ?? ?? ?? ?? ?? ?? ?? 48 31 d1 8a 40 08 34 ?? 48 89 8c 24 ?? ?? ?? ?? 88 84 24 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}