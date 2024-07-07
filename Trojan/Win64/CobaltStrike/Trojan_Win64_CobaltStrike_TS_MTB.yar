
rule Trojan_Win64_CobaltStrike_TS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b ca 41 8b d3 d3 ea 8a 08 48 8b 46 90 01 01 80 f1 90 01 01 22 d1 48 63 8e 90 01 04 88 14 01 ff 86 90 01 04 48 8b 86 90 01 04 48 8b 8e 90 01 04 4c 31 76 90 01 01 48 0b cf 48 81 76 90 01 05 48 0f af c1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}