
rule Trojan_Win64_CobaltStrike_AMR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 48 63 d0 48 8b 45 10 48 01 d0 8b 55 fc 48 63 ca 48 8b 55 10 48 01 ca 0f b6 12 83 f2 9a 88 10 83 45 fc 01 8b 45 18 83 e8 01 3b 45 fc 7f cf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}