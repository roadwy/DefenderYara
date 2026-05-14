
rule Trojan_Win64_CobaltStrike_FK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b d6 4c 8d 0d ?? ?? ?? ?? 0f 1f 40 00 0f 1f 84 00 00 00 00 00 48 8d 41 05 ff c1 83 e0 1f 48 8d 52 01 42 0f b6 04 08 30 42 ff 48 63 c1 48 3b c7 72 } //10
		$a_81_1 = {52 51 56 77 6c 54 6f 45 4d 4f 79 6b 31 51 71 4f 57 49 43 70 71 53 65 73 72 66 6f 6d 74 6d 49 52 } //1 RQVwlToEMOyk1QqOWICpqSesrfomtmIR
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}