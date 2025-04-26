
rule PWS_Win32_Ldpinch{
	meta:
		description = "PWS:Win32/Ldpinch,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 09 00 0e 00 00 "
		
	strings :
		$a_02_0 = {53 75 62 6a 65 63 74 3a 20 50 61 73 73 [0-05] 20 66 72 6f 6d } //2
		$a_02_1 = {26 62 3d 50 61 73 73 65 73 20 66 72 6f 6d 20 ?? 69 6e 63 68 } //2
		$a_00_2 = {5c 61 6e 64 72 71 2e 69 6e 69 } //1 \andrq.ini
		$a_00_3 = {53 6f 66 74 77 61 72 65 5c 46 61 72 5c 50 6c 75 67 69 6e 5c 46 54 50 5c 48 6f 73 74 73 } //1 Software\Far\Plugin\FTP\Hosts
		$a_01_4 = {50 53 74 6f 72 65 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 PStoreCreateInstance
		$a_01_5 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 4e 61 6d 65 41 } //1 LookupAccountNameA
		$a_01_6 = {52 61 73 45 6e 75 6d 45 6e 74 72 69 65 73 41 } //1 RasEnumEntriesA
		$a_00_7 = {5c 57 63 78 5f 66 74 70 2e 69 6e 69 } //1 \Wcx_ftp.ini
		$a_00_8 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 32 } //1 POP3 Password2
		$a_00_9 = {53 6f 66 74 77 61 72 65 5c 47 68 69 73 6c 65 72 5c 54 6f 74 61 6c 20 43 6f 6d 6d 61 6e 64 65 72 } //1 Software\Ghisler\Total Commander
		$a_00_10 = {53 4f 46 54 57 41 52 45 5c 52 49 54 5c 54 68 65 20 42 61 74 21 } //1 SOFTWARE\RIT\The Bat!
		$a_00_11 = {53 4f 46 54 57 41 52 45 5c 4d 69 72 61 62 69 6c 69 73 5c 49 43 51 5c 44 65 66 61 75 6c 74 50 72 65 66 73 } //1 SOFTWARE\Mirabilis\ICQ\DefaultPrefs
		$a_00_12 = {63 72 79 70 74 65 64 2d 70 61 73 73 77 6f 72 64 } //1 crypted-password
		$a_00_13 = {6e 65 63 74 69 6f 6e 73 5c 70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //1 nections\pbk\rasphone.pbk
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1) >=9
 
}
rule PWS_Win32_Ldpinch_2{
	meta:
		description = "PWS:Win32/Ldpinch,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 16 00 00 "
		
	strings :
		$a_02_0 = {53 75 62 6a 65 63 74 3a 20 50 61 73 73 [0-05] 20 66 72 6f 6d } //2
		$a_02_1 = {26 62 3d 50 61 73 73 65 73 20 66 72 6f 6d 20 ?? 69 6e 63 68 } //2
		$a_00_2 = {5c 61 6e 64 72 71 2e 69 6e 69 } //1 \andrq.ini
		$a_02_3 = {53 6f 66 74 77 61 72 65 5c 46 61 72 5c 50 6c 75 67 69 6e [0-01] 5c 46 54 50 5c 48 6f 73 74 73 } //1
		$a_01_4 = {50 53 74 6f 72 65 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 PStoreCreateInstance
		$a_01_5 = {4c 6f 6f 6b 75 70 41 63 63 6f 75 6e 74 4e 61 6d 65 41 } //1 LookupAccountNameA
		$a_01_6 = {52 61 73 45 6e 75 6d 45 6e 74 72 69 65 73 41 } //1 RasEnumEntriesA
		$a_00_7 = {5c 57 63 78 5f 66 74 70 2e 69 6e 69 } //1 \Wcx_ftp.ini
		$a_00_8 = {50 4f 50 33 20 50 61 73 73 77 6f 72 64 32 } //1 POP3 Password2
		$a_00_9 = {53 6f 66 74 77 61 72 65 5c 47 68 69 73 6c 65 72 5c 54 6f 74 61 6c 20 43 6f 6d 6d 61 6e 64 65 72 } //1 Software\Ghisler\Total Commander
		$a_00_10 = {53 4f 46 54 57 41 52 45 5c 52 49 54 5c 54 68 65 20 42 61 74 21 } //1 SOFTWARE\RIT\The Bat!
		$a_00_11 = {53 4f 46 54 57 41 52 45 5c 4d 69 72 61 62 69 6c 69 73 5c 49 43 51 5c 44 65 66 61 75 6c 74 50 72 65 66 73 } //1 SOFTWARE\Mirabilis\ICQ\DefaultPrefs
		$a_00_12 = {63 72 79 70 74 65 64 2d 70 61 73 73 77 6f 72 64 } //1 crypted-password
		$a_00_13 = {6e 65 63 74 69 6f 6e 73 5c 70 62 6b 5c 72 61 73 70 68 6f 6e 65 2e 70 62 6b } //1 nections\pbk\rasphone.pbk
		$a_00_14 = {53 6f 66 74 77 61 72 65 5c 52 69 6d 41 72 74 73 5c 42 32 5c 53 65 74 74 69 6e 67 73 } //1 Software\RimArts\B2\Settings
		$a_00_15 = {5c 47 6c 6f 62 61 6c 53 43 41 50 45 5c 43 75 74 65 46 54 50 } //1 \GlobalSCAPE\CuteFTP
		$a_00_16 = {53 6f 66 74 77 61 72 65 5c 4d 61 69 6c 2e 52 75 5c 41 67 65 6e 74 5c 6d 72 61 5f 6c 6f 67 69 6e 73 } //1 Software\Mail.Ru\Agent\mra_logins
		$a_00_17 = {53 4f 46 54 57 41 52 45 5c 46 6c 61 73 68 46 58 50 5c 33 } //1 SOFTWARE\FlashFXP\3
		$a_00_18 = {5c 77 73 5f 66 74 70 2e 69 6e 69 } //1 \ws_ftp.ini
		$a_00_19 = {68 74 74 70 3a 2f 2f 73 70 6f 74 61 75 64 69 74 6f 72 2e 6e 73 61 75 64 69 74 6f 72 2e 63 6f 6d } //-1 http://spotauditor.nsauditor.com
		$a_00_20 = {43 68 61 6e 67 65 20 46 6f 72 67 6f 74 74 65 6e 20 50 61 73 73 77 6f 72 64 20 68 74 74 70 3a 2f 2f 77 77 77 2e 63 68 61 6e 67 65 2d 66 6f 72 67 6f 74 74 65 6e 2d 70 61 73 73 77 6f 72 64 2e 63 6f 6d } //-100 Change Forgotten Password http://www.change-forgotten-password.com
		$a_00_21 = {68 74 74 70 3a 2f 2f 77 77 77 2e 74 6f 70 2d 70 61 73 73 77 6f 72 64 2e 63 6f 6d 2f 70 61 73 73 77 6f 72 64 2d 72 65 63 6f 76 65 72 79 2d 62 75 6e 64 6c 65 2e 68 74 6d 6c } //-100 http://www.top-password.com/password-recovery-bundle.html
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*-1+(#a_00_20  & 1)*-100+(#a_00_21  & 1)*-100) >=9
 
}