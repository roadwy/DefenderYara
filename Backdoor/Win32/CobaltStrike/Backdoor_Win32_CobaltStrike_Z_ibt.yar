
rule Backdoor_Win32_CobaltStrike_Z_ibt{
	meta:
		description = "Backdoor:Win32/CobaltStrike.Z!ibt,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_80_0 = {41 55 54 4f 90 00 } //AUTO�  5
		$a_03_1 = {8b fa 89 1c 24 33 f6 85 d2 7e 16 8b cb 8b d8 8b 03 33 d2 f7 f5 41 83 c3 ?? 46 88 51 ff 3b f7 7c ee 8b 04 24 89 2d 44 a0 40 00 83 c4 04 5d 5f 5e } //5
	condition:
		((#a_80_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}