
rule Trojan_Win64_CobaltStrike_CBVV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CBVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 b9 04 00 00 00 41 b8 00 30 00 00 ba 10 3a 04 00 33 c9 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}