
rule Trojan_Win64_CobaltStrike_CCFL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 01 de 41 c1 ee ?? 43 8d 1c b6 41 8d 1c 9e 41 89 f6 41 29 de 42 0f b6 1c 32 32 1c 37 88 1c 31 ff c6 83 fe ?? 4c 89 c7 48 0f 44 f8 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}