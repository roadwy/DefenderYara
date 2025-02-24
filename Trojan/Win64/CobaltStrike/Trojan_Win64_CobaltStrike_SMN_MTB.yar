
rule Trojan_Win64_CobaltStrike_SMN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 b8 76 4e af cc fb a9 1d 4e 8b 14 01 48 8b 0d a0 3b 0f 00 8b 0c 01 41 89 d0 41 ff c8 41 0f af d0 41 88 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}