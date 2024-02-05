
rule Backdoor_Win32_Hupigon_FC{
	meta:
		description = "Backdoor:Win32/Hupigon.FC,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {8b d7 66 81 f2 3b 01 88 50 01 } //02 00 
		$a_00_1 = {83 ea 41 6b d2 1a } //02 00 
		$a_00_2 = {69 c0 0b 35 00 00 05 68 60 00 00 } //02 00 
		$a_02_3 = {83 e2 01 4a 0f 94 45 90 01 01 83 e0 01 48 0f 94 45 90 01 01 83 ff 30 90 00 } //01 00 
		$a_00_4 = {8d 04 19 48 33 d2 f7 f1 f7 e9 } //01 00 
		$a_00_5 = {8b f0 85 f6 74 0c 8b 04 24 50 55 ff d6 85 c0 0f 94 c3 } //00 00 
	condition:
		any of ($a_*)
 
}