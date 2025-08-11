
rule Trojan_Win64_Lazy_BOE_MTB{
	meta:
		description = "Trojan:Win64/Lazy.BOE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c0 e9 03 c0 e0 05 08 c8 34 a0 41 88 04 24 49 8b 76 18 48 8b 05 ?? ?? ?? ?? 4c 01 f8 ff d0 48 98 48 8d 0d a8 17 24 00 48 3b 34 c1 0f 86 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}