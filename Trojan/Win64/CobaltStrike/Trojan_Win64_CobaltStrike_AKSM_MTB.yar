
rule Trojan_Win64_CobaltStrike_AKSM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AKSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 83 c1 10 } //01 00 
		$a_01_1 = {73 79 73 74 65 6d 69 6e 66 6f 2e 74 78 74 } //00 00  systeminfo.txt
	condition:
		any of ($a_*)
 
}