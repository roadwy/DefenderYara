
rule Trojan_Win64_CobaltStrike_CCIL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b9 40 00 00 00 41 b8 00 10 00 00 48 89 d3 48 89 ce 31 c9 ff 15 ?? ?? ?? ?? 49 89 d8 48 89 f2 48 89 c1 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}