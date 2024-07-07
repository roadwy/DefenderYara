
rule Trojan_Win64_CobaltStrike_SJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ca 41 33 91 90 01 04 81 f1 90 01 04 41 90 01 06 81 f2 90 01 04 41 90 01 06 41 90 01 06 41 90 01 03 41 90 01 03 41 90 01 06 49 90 01 06 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}