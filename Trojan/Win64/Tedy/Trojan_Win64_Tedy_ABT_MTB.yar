
rule Trojan_Win64_Tedy_ABT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ABT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 3b c8 48 8d 52 01 b8 ?? ?? ?? ?? 41 0f 43 c1 ff c1 32 44 32 ?? 88 44 3a ?? 3b cb 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}