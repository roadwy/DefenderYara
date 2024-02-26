
rule Trojan_Win64_CobaltStrike_YAJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {86 d2 32 c3 86 db 90 13 86 c0 c0 c8 29 90 90 90 13 aa 90 90 90 90 90 13 48 ff c9 90 90 86 db 90 13 90 13 ac 90 13 32 c3 90 90 02 c3 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}