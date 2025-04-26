
rule Trojan_Win64_CobaltStrike_CCIB_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 63 44 24 20 48 8d 54 24 40 48 8b 4c 24 70 48 8b 0c c1 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}