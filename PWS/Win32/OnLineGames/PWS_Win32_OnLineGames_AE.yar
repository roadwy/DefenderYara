
rule PWS_Win32_OnLineGames_AE{
	meta:
		description = "PWS:Win32/OnLineGames.AE,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 10 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 20 56 57 ff 15 ?? ?? 40 00 33 f6 56 56 56 ff 15 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 56 56 8d 45 e0 56 50 ff ?? ?? 10 40 00 8d 45 fc 50 6a 20 ff 15 ?? ?? 40 00 50 ff 15 ?? ?? 40 00 6a 01 68 ?? ?? 40 00 ff 75 fc e8 aa fe ff ff 83 c4 0c 68 ?? ?? 40 00 6a 01 56 ff 15 ?? ?? 40 00 8b f8 ff 15 ?? ?? 40 00 } //20
		$a_00_1 = {62 75 74 74 6f 6e 2d 72 65 64 2d 73 65 63 75 72 69 74 79 74 6f 6b 65 6e 2e 67 69 66 } //1 button-red-securitytoken.gif
		$a_00_2 = {77 65 69 74 65 72 5f 7a 75 5f 66 6d 2e 67 69 66 } //1 weiter_zu_fm.gif
		$a_00_3 = {77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 } //1 worldofwarcraft
		$a_00_4 = {50 61 73 73 77 64 } //1 Passwd
		$a_00_5 = {77 65 62 67 65 74 } //1 webget
		$a_00_6 = {77 77 77 2e 79 6f 75 74 75 62 65 39 39 39 2e 63 6f 6d } //1 www.youtube999.com
		$a_00_7 = {67 72 75 6e 74 2e 77 6f 77 63 68 69 6e 61 2e 63 6f 6d } //1 grunt.wowchina.com
		$a_00_8 = {6b 72 2e 76 65 72 73 69 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 kr.version.worldofwarcraft.com
		$a_00_9 = {6b 72 2e 6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 kr.logon.worldofwarcraft.com
		$a_00_10 = {75 73 2e 76 65 72 73 69 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 us.version.worldofwarcraft.com
		$a_00_11 = {75 73 2e 6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 us.logon.worldofwarcraft.com
		$a_00_12 = {74 77 2e 76 65 72 73 69 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 tw.version.worldofwarcraft.com
		$a_00_13 = {74 77 2e 6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 tw.logon.worldofwarcraft.com
		$a_00_14 = {65 75 2e 76 65 72 73 69 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 eu.version.worldofwarcraft.com
		$a_00_15 = {65 75 2e 6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 eu.logon.worldofwarcraft.com
	condition:
		((#a_03_0  & 1)*20+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1) >=23
 
}