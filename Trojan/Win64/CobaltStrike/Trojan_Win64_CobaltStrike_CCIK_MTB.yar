
rule Trojan_Win64_CobaltStrike_CCIK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CCIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 03 d1 48 8b ca 48 0f be 09 48 33 c8 48 8b c1 48 8b 8d } //00 00 
	condition:
		any of ($a_*)
 
}