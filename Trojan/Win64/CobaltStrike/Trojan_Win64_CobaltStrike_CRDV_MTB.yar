
rule Trojan_Win64_CobaltStrike_CRDV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CRDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 b9 40 00 00 00 48 63 d8 41 b8 00 10 00 00 48 8b d3 33 c9 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}