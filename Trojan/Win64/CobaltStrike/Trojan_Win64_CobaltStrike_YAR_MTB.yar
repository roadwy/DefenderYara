
rule Trojan_Win64_CobaltStrike_YAR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {80 75 b0 43 80 75 b1 6c 80 75 b2 6f 80 75 b3 73 80 75 b4 65 80 75 b5 48 80 75 b6 61 80 75 b7 6e 80 75 b8 64 80 75 b9 6c 80 75 ba 65 80 75 bb 43 80 75 bc 6c 80 75 bd 6f } //00 00 
	condition:
		any of ($a_*)
 
}