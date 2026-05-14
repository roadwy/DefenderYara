
rule Trojan_Win32_CobaltStrike_FJ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8d 04 0a 25 1f 00 00 80 79 05 48 83 c8 e0 40 8a 80 ?? ?? ?? ?? 30 01 41 83 ee 01 75 } //10
		$a_03_1 = {ba 05 00 00 00 8b cb 2b d3 [0-01] 8d 04 0a 83 e0 1f 8d 49 01 8a 80 ?? ?? ?? ?? 30 41 ff 83 ee 01 75 } //10
		$a_81_2 = {52 51 56 77 6c 54 6f 45 4d 4f 79 6b 31 51 71 4f 57 49 43 70 71 53 65 73 72 66 6f 6d 74 6d 49 52 } //1 RQVwlToEMOyk1QqOWICpqSesrfomtmIR
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_81_2  & 1)*1) >=11
 
}