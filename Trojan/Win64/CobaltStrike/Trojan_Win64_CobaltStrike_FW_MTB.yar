
rule Trojan_Win64_CobaltStrike_FW_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 2b 83 90 01 04 89 4b 90 01 01 83 f0 90 01 01 41 0f af c1 89 43 90 01 01 8b 4b 90 01 01 2b ca 81 c1 90 01 04 31 4b 90 01 01 49 81 fb 90 01 04 0f 8c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}