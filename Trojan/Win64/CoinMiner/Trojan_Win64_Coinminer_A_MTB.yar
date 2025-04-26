
rule Trojan_Win64_Coinminer_A_MTB{
	meta:
		description = "Trojan:Win64/Coinminer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 55 9c 49 bd a8 2a a1 df ad 5d 93 cf 4d 33 ed 4f 8d ?? ?? ?? ?? ?? ?? 66 41 f7 d5 4e 8b ?? ?? ?? ?? ?? ?? 48 c7 44 24 08 ?? ?? ?? ?? ff 74 24 00 9d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}