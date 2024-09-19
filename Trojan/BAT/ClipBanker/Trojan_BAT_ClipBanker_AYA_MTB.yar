
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