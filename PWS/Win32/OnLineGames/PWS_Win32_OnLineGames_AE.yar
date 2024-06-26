
rule PWS_Win32_OnLineGames_AE{
	meta:
		description = "PWS:Win32/OnLineGames.AE,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 10 00 00 14 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 20 56 57 ff 15 90 01 02 40 00 33 f6 56 56 56 ff 15 90 01 02 40 00 50 ff 15 90 01 02 40 00 56 56 8d 45 e0 56 50 ff 90 01 02 10 40 00 8d 45 fc 50 6a 20 ff 15 90 01 02 40 00 50 ff 15 90 01 02 40 00 6a 01 68 90 01 02 40 00 ff 75 fc e8 aa fe ff ff 83 c4 0c 68 90 01 02 40 00 6a 01 56 ff 15 90 01 02 40 00 8b f8 ff 15 90 01 02 40 00 90 00 } //01 00 
		$a_00_1 = {62 75 74 74 6f 6e 2d 72 65 64 2d 73 65 63 75 72 69 74 79 74 6f 6b 65 6e 2e 67 69 66 } //01 00  button-red-securitytoken.gif
		$a_00_2 = {77 65 69 74 65 72 5f 7a 75 5f 66 6d 2e 67 69 66 } //01 00  weiter_zu_fm.gif
		$a_00_3 = {77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 } //01 00  worldofwarcraft
		$a_00_4 = {50 61 73 73 77 64 } //01 00  Passwd
		$a_00_5 = {77 65 62 67 65 74 } //01 00  webget
		$a_00_6 = {77 77 77 2e 79 6f 75 74 75 62 65 39 39 39 2e 63 6f 6d } //01 00  www.youtube999.com
		$a_00_7 = {67 72 75 6e 74 2e 77 6f 77 63 68 69 6e 61 2e 63 6f 6d } //01 00  grunt.wowchina.com
		$a_00_8 = {6b 72 2e 76 65 72 73 69 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //01 00  kr.version.worldofwarcraft.com
		$a_00_9 = {6b 72 2e 6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //01 00  kr.logon.worldofwarcraft.com
		$a_00_10 = {75 73 2e 76 65 72 73 69 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //01 00  us.version.worldofwarcraft.com
		$a_00_11 = {75 73 2e 6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //01 00  us.logon.worldofwarcraft.com
		$a_00_12 = {74 77 2e 76 65 72 73 69 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //01 00  tw.version.worldofwarcraft.com
		$a_00_13 = {74 77 2e 6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //01 00  tw.logon.worldofwarcraft.com
		$a_00_14 = {65 75 2e 76 65 72 73 69 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //01 00  eu.version.worldofwarcraft.com
		$a_00_15 = {65 75 2e 6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //00 00  eu.logon.worldofwarcraft.com
	condition:
		any of ($a_*)
 
}