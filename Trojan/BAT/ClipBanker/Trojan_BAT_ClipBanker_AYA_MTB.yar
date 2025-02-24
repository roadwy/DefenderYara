
rule Trojan_BAT_ClipBanker_AYA_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 30 36 39 65 37 64 62 61 2d 33 62 36 38 2d 34 35 62 34 2d 61 38 37 33 2d 34 32 34 38 37 33 37 30 63 62 32 65 } //2 $069e7dba-3b68-45b4-a873-42487370cb2e
		$a_01_1 = {53 74 65 61 6c 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 Steal.g.resources
		$a_01_2 = {53 74 65 61 6c 2e 65 78 65 } //1 Steal.exe
		$a_01_3 = {49 45 4a 41 45 4a 4b 46 47 4f 41 43 41 4d 48 44 4e 4f 44 42 4c 44 48 50 4b 41 44 4c 4b 4b 4f 48 43 44 48 45 } //1 IEJAEJKFGOACAMHDNODBLDHPKADLKKOHCDHE
		$a_01_4 = {44 00 65 00 62 00 75 00 67 00 67 00 65 00 72 00 20 00 44 00 65 00 74 00 65 00 63 00 74 00 65 00 64 00 } //1 Debugger Detected
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule Trojan_BAT_ClipBanker_AYA_MTB_2{
	meta:
		description = "Trojan:BAT/ClipBanker.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 63 62 37 39 64 61 38 34 2d 39 38 63 62 2d 34 64 38 33 2d 62 33 31 35 2d 30 33 32 64 33 35 37 35 38 38 31 62 } //3 $cb79da84-98cb-4d83-b315-032d3575881b
		$a_00_1 = {2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 73 00 63 00 20 00 4d 00 49 00 4e 00 55 00 54 00 45 00 20 00 2f 00 6d 00 6f 00 20 00 31 00 20 00 2f 00 74 00 6e 00 20 00 22 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 22 00 20 00 2f 00 74 00 72 00 } //1 /create /sc MINUTE /mo 1 /tn "Windows Service" /tr
		$a_00_2 = {74 00 61 00 73 00 6b 00 68 00 6f 00 73 00 74 00 6d 00 67 00 72 00 36 00 34 00 2e 00 65 00 78 00 65 00 } //1 taskhostmgr64.exe
		$a_01_3 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
		$a_01_4 = {4b 4d 53 41 75 74 6f 4c 69 74 65 2e 50 72 6f 70 65 72 74 69 65 73 } //1 KMSAutoLite.Properties
		$a_01_5 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}