
rule Backdoor_Win64_CobaltStrike_MCK_MTB{
	meta:
		description = "Backdoor:Win64/CobaltStrike.MCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 49 63 d2 49 3b d1 4d 8d 5b 01 48 0f 45 ce 42 0f b6 04 01 48 8d 71 01 41 30 43 ff 33 c0 49 3b d1 41 0f 45 c2 ff c3 44 8d 50 01 48 63 c3 48 3b c7 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}