
rule Trojan_Win64_Fabookie_NFA_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c9 48 03 cf 48 8d 55 e0 41 b8 ?? ?? ?? ?? e8 3f a2 01 00 85 c0 74 14 ff c3 48 63 cb 48 81 f9 ?? ?? ?? ?? 72 dc 48 8b 45 10 } //5
		$a_03_1 = {33 d2 83 7b 30 ?? 75 19 39 53 3c 74 14 48 8d 1d 66 ff ff ff } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}