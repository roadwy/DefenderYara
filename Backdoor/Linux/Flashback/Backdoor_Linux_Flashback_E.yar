
rule Backdoor_Linux_Flashback_E{
	meta:
		description = "Backdoor:Linux/Flashback.E,SIGNATURE_TYPE_MACHOHSTR_EXT,0f 00 0e 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 } //01 00  IOPlatformUUID
		$a_01_1 = {75 70 64 61 74 65 3f 69 66 3d 25 26 66 75 3d 25 75 } //01 00  update?if=%&fu=%u
		$a_01_2 = {6c 61 75 6e 63 68 63 74 6c 20 6c 6f 61 64 } //01 00  launchctl load
		$a_01_3 = {7c 6f 6c 64 75 70 64 61 74 65 } //01 00  |oldupdate
		$a_01_4 = {7c 3c 67 3e 7c } //01 00  |<g>|
		$a_01_5 = {73 75 64 6f 20 2d 75 } //0a 00  sudo -u
		$a_01_6 = {36 36 34 39 32 33 34 3b 38 35 37 35 33 34 33 } //00 00  6649234;8575343
	condition:
		any of ($a_*)
 
}
rule Backdoor_Linux_Flashback_E_2{
	meta:
		description = "Backdoor:Linux/Flashback.E,SIGNATURE_TYPE_MACHOHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 } //01 00  IOPlatformUUID
		$a_01_1 = {2f 63 6c 69 63 6b 3f 64 61 74 61 3d } //01 00  /click?data=
		$a_01_2 = {2f 73 65 61 72 63 68 3f 71 3d } //01 00  /search?q=
		$a_01_3 = {47 45 54 20 2f 75 72 6c 3f } //01 00  GET /url?
		$a_01_4 = {42 49 44 4f 4b } //01 00  BIDOK
		$a_01_5 = {77 69 6e 64 6f 77 2e 67 6f 6f 67 6c 65 4a 61 76 61 53 63 72 69 70 74 52 65 64 69 72 65 63 74 3d 31 } //01 00  window.googleJavaScriptRedirect=1
		$a_01_6 = {31 32 33 34 64 36 37 38 3b 38 61 36 35 34 33 32 31 } //01 00  1234d678;8a654321
		$a_01_7 = {d0 e3 e4 e6 ee d6 00 d0 f8 ee e7 ed d6 } //00 00 
	condition:
		any of ($a_*)
 
}