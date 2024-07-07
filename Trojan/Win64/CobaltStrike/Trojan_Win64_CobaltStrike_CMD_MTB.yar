
rule Trojan_Win64_CobaltStrike_CMD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c1 48 8b 95 e0 4f 00 00 8b 85 d4 4f 00 00 48 98 88 0c 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}