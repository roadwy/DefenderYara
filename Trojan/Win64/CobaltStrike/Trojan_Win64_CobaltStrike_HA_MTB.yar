
rule Trojan_Win64_CobaltStrike_HA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {81 7c 24 04 8e 4e 0e ec 74 36 81 7c 24 04 aa fc 0d 7c 74 2c 81 7c 24 04 54 ca af 91 74 22 81 7c 24 04 1b c6 46 79 74 18 81 7c 24 04 fc a4 53 07 74 0e 81 7c 24 04 04 49 32 d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}