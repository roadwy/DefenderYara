
rule Backdoor_BAT_Geratid_A_dll{
	meta:
		description = "Backdoor:BAT/Geratid.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,ffffffd4 01 ffffff9e 01 0b 00 00 ffffffc8 00 "
		
	strings :
		$a_01_0 = {48 61 72 64 77 61 72 65 49 44 00 52 41 54 49 44 00 57 65 62 49 6e 74 65 72 70 72 65 74 65 72 } //c8 00 
		$a_01_1 = {49 64 65 6e 74 69 66 69 63 61 74 69 6f 6e 46 72 6f 6d 55 52 4c } //32 00  IdentificationFromURL
		$a_01_2 = {75 6e 6c 6f 63 6b 41 73 73 69 73 74 42 69 6e 00 75 6e 6c 6f 63 6b 41 73 73 69 73 74 4e 61 6d 65 } //32 00  湵潬正獁楳瑳楂n湵潬正獁楳瑳慎敭
		$a_01_3 = {52 75 6e 42 61 74 63 68 00 76 61 6c 75 65 73 00 44 69 73 63 6f 6e 6e 65 63 74 00 45 78 65 63 46 72 6f 6d 55 72 6c } //04 00  畒䉮瑡档瘀污敵s楄捳湯敮瑣䔀數䙣潲啭汲
		$a_01_4 = {22 43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 22 } //04 00  "C:\Windows\iexplore.exe"
		$a_01_5 = {67 65 74 5f 46 69 72 65 77 61 6c 6c 4e 61 6d 65 } //04 00  get_FirewallName
		$a_01_6 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //04 00  SELECT * FROM AntivirusProduct
		$a_01_7 = {5f 00 50 00 55 00 42 00 4c 00 49 00 43 00 31 00 32 00 32 00 39 00 } //04 00  _PUBLIC1229
		$a_01_8 = {4b 69 6c 6c 50 72 6f 63 65 73 73 46 72 6f 6d 46 69 6c 65 49 6e 66 6f } //01 00  KillProcessFromFileInfo
		$a_01_9 = {67 65 74 5f 41 56 4e 61 6d 65 } //01 00  get_AVName
		$a_01_10 = {53 65 74 52 41 54 49 44 } //00 00  SetRATID
	condition:
		any of ($a_*)
 
}