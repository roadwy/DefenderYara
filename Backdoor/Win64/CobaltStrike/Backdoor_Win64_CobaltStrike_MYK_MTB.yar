
rule Backdoor_Win64_CobaltStrike_MYK_MTB{
	meta:
		description = "Backdoor:Win64/CobaltStrike.MYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 f7 29 fa 89 d7 81 c7 90 02 04 0f bf ff 69 ff 90 02 04 c1 ef 10 01 d7 81 c7 90 1b 00 21 cf 89 fe c1 ee 0f c1 ef 06 01 f7 89 fe c1 e6 07 29 f7 01 fa 81 c2 90 1b 00 88 54 04 20 48 ff c0 48 83 f8 90 02 01 75 90 00 } //01 00 
		$a_03_1 = {01 fa 81 c2 90 02 04 0f bf d2 69 d2 90 02 04 c1 ea 10 01 f2 83 c2 90 02 01 21 ca 89 d7 c1 ef 0f c1 ea 06 01 fa 89 d7 c1 e7 07 29 fa 01 f2 83 c2 90 1b 02 88 54 04 20 48 ff c0 48 83 f8 90 02 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}