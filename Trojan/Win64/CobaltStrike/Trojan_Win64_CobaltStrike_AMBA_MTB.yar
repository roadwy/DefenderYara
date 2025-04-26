
rule Trojan_Win64_CobaltStrike_AMBA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 ?? 8a 54 15 ?? 32 14 07 41 88 14 00 48 ff c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}