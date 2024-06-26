
rule Worm_Win32_Dorkbot_I{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 6f 64 75 6c 65 33 00 50 72 6f 79 65 63 74 6f 31 00 } //01 00  潍畤敬3牐祯捥潴1
		$a_01_1 = {c7 85 a0 fd ff ff 83 00 00 00 c7 85 98 fd ff ff 02 00 00 00 8d 95 98 fd ff ff 8b 45 d8 6a 23 59 2b 48 14 c1 e1 04 8b 45 d8 8b 40 0c 03 c8 e9 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Dorkbot_I_2{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 4d 5a 00 00 74 05 e9 7c 01 00 00 8b 0d 90 01 04 8b 55 08 03 51 3c 89 15 90 01 04 a1 90 01 04 81 38 50 45 00 00 74 05 90 00 } //01 00 
		$a_01_1 = {74 13 8b 4d fc 03 4d f8 0f be 11 f7 d2 8b 45 fc 03 45 f8 88 10 eb 92 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Dorkbot_I_3{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 5c 70 72 6f 67 72 61 6d 64 61 74 61 } //01 00  %s\programdata
		$a_00_1 = {25 73 5c 52 65 63 79 63 6c 65 72 } //01 00  %s\Recycler
		$a_00_2 = {25 73 5c 2a 2e 2a } //01 00  %s\*.*
		$a_00_3 = {5c 55 70 64 61 74 65 5c } //01 00  \Update\
		$a_01_4 = {6a 00 6a 02 8b f8 c7 44 24 20 28 01 00 00 ff 15 } //00 00 
		$a_00_5 = {78 57 00 } //00 08 
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Dorkbot_I_4{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {23 72 6e 64 62 6f 74 } //01 00  #rndbot
		$a_00_1 = {23 72 6e 64 66 74 70 } //01 00  #rndftp
		$a_00_2 = {6e 67 72 2e 68 6f 73 74 6e 61 6d 65 } //01 00  ngr.hostname
		$a_00_3 = {5b 53 6c 6f 77 6c 6f 72 69 73 5d 3a } //05 00  [Slowloris]:
		$a_01_4 = {76 4e 80 3e 53 75 18 80 7e 01 44 75 12 80 7e 02 47 75 0c 68 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Dorkbot_I_5{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 73 2e 70 32 31 2d 3e 20 4d 65 73 73 61 67 65 20 68 69 6a 61 63 6b 65 64 21 00 00 6d 73 6e 6d 73 67 00 00 6d 73 6e 69 6e 74 00 00 62 61 64 64 72 00 00 00 58 2d 4d 4d 53 2d 49 4d 2d 46 6f 72 6d 61 74 3a 00 00 00 00 43 41 4c 20 25 64 20 25 32 35 36 73 00 00 00 00 6d 73 6e 75 00 00 00 00 44 6f 6e 65 20 66 72 73 74 0a 00 00 6e 67 72 2d 3e 62 6c 6f 63 6b 73 69 7a 65 3a 20 25 64 0a 00 62 6c 6f 63 6b 5f 73 69 7a 65 3a 20 25 64 0a 00 4e 74 46 72 65 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Dorkbot_I_6{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 02 00 "
		
	strings :
		$a_81_0 = {2a 2e 67 6f 6e 65 77 69 74 68 74 68 65 77 69 6e 67 73 } //01 00  *.gonewiththewings
		$a_02_1 = {2f 00 43 00 52 00 45 00 41 00 54 00 45 00 20 00 2f 00 53 00 43 00 20 00 4f 00 4e 00 4c 00 4f 00 47 00 4f 00 4e 00 20 00 2f 00 54 00 4e 00 20 00 22 00 90 02 20 22 00 20 00 2f 00 54 00 52 00 20 00 22 00 25 00 73 00 22 00 20 00 2f 00 52 00 4c 00 20 00 48 00 49 00 47 00 48 00 45 00 53 00 54 00 90 00 } //01 00 
		$a_02_2 = {2f 43 52 45 41 54 45 20 2f 53 43 20 4f 4e 4c 4f 47 4f 4e 20 2f 54 4e 20 22 90 02 20 22 20 2f 54 52 20 22 25 73 22 20 2f 52 4c 20 48 49 47 48 45 53 54 90 00 } //01 00 
		$a_80_3 = {2f 63 20 22 25 25 53 79 73 74 65 6d 52 6f 6f 74 25 25 5c 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 25 25 63 64 25 25 25 73 20 26 } ///c "%%SystemRoot%%\explorer.exe %%cd%%%s &  01 00 
		$a_80_4 = {61 74 74 72 69 62 20 2d 73 20 2d 68 20 25 25 63 64 25 25 25 73 20 26 20 78 63 6f 70 79 20 2f 46 20 2f 53 20 2f 51 20 2f 48 20 2f 52 20 2f 59 20 25 25 63 64 25 25 25 73 20 25 25 74 65 6d 70 25 25 5c 25 73 } //attrib -s -h %%cd%%%s & xcopy /F /S /Q /H /R /Y %%cd%%%s %%temp%%\%s  00 00 
	condition:
		any of ($a_*)
 
}
rule Worm_Win32_Dorkbot_I_7{
	meta:
		description = "Worm:Win32/Dorkbot.I,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 15 00 00 0a 00 "
		
	strings :
		$a_00_0 = {6e 67 72 42 6f 74 } //02 00  ngrBot
		$a_00_1 = {6e 67 72 2d 3e 62 6c 6f 63 6b 73 69 7a 65 3a 20 25 64 } //01 00  ngr->blocksize: %d
		$a_00_2 = {25 73 2e 42 6c 6f 63 6b 65 64 20 22 25 73 22 20 66 72 6f 6d 20 72 65 6d 6f 76 69 6e 67 20 6f 75 72 20 62 6f 74 20 66 69 6c 65 21 } //01 00  %s.Blocked "%s" from removing our bot file!
		$a_00_3 = {73 74 61 72 74 20 25 25 63 64 25 25 52 45 43 59 43 4c 45 52 5c 25 73 } //01 00  start %%cd%%RECYCLER\%s
		$a_00_4 = {5b 76 3d 22 25 73 22 20 63 3d 22 25 73 22 20 68 3d 22 25 73 22 20 70 3d 22 25 53 22 5d } //05 00  [v="%s" c="%s" h="%s" p="%S"]
		$a_03_5 = {5b 53 6c 6f 77 6c 6f 72 69 73 5d 3a 20 90 01 08 20 66 6c 6f 6f 64 20 6f 6e 20 22 25 73 22 90 00 } //01 00 
		$a_00_6 = {5b 55 44 50 5d 3a 20 53 74 61 72 74 69 6e 67 20 66 6c 6f 6f 64 20 6f 6e 20 } //01 00  [UDP]: Starting flood on 
		$a_00_7 = {5b 53 59 4e 5d 3a 20 53 74 61 72 74 69 6e 67 20 66 6c 6f 6f 64 20 6f 6e 20 } //01 00  [SYN]: Starting flood on 
		$a_00_8 = {5b 55 53 42 5d 3a 20 49 6e 66 65 63 74 65 64 20 25 73 } //01 00  [USB]: Infected %s
		$a_00_9 = {5b 4d 53 4e 5d 3a 20 55 70 64 61 74 65 64 20 4d 53 4e 20 73 70 72 65 61 64 } //01 00  [MSN]: Updated MSN spread
		$a_00_10 = {5b 48 54 54 50 5d 3a 20 55 70 64 61 74 65 64 20 48 54 54 50 20 73 70 72 65 61 64 } //01 00  [HTTP]: Updated HTTP spread
		$a_00_11 = {5b 48 54 54 50 5d 3a 20 49 6e 6a 65 63 74 65 64 20 76 61 6c 75 65 20 69 73 20 6e 6f 77 20 25 73 } //01 00  [HTTP]: Injected value is now %s
		$a_00_12 = {5b 75 73 62 3d 22 25 64 22 20 6d 73 6e 3d 22 25 64 22 20 68 74 74 70 3d 22 25 64 22 20 74 6f 74 61 6c 3d 22 25 64 22 5d } //01 00  [usb="%d" msn="%d" http="%d" total="%d"]
		$a_00_13 = {5b 66 74 70 3d 22 25 64 22 20 70 6f 70 3d 22 25 64 22 20 68 74 74 70 3d 22 25 64 22 20 74 6f 74 61 6c 3d 22 25 64 22 5d } //01 00  [ftp="%d" pop="%d" http="%d" total="%d"]
		$a_00_14 = {5b 46 54 50 20 49 6e 66 65 63 74 5d 3a 20 25 73 20 77 61 73 20 69 66 72 61 6d 65 64 } //01 00  [FTP Infect]: %s was iframed
		$a_00_15 = {5b 52 75 73 6b 69 6c 6c 5d 3a 20 44 65 74 65 63 74 65 64 20 46 69 6c 65 3a 20 22 25 73 22 } //01 00  [Ruskill]: Detected File: "%s"
		$a_00_16 = {66 74 70 69 6e 66 65 63 74 } //01 00  ftpinfect
		$a_00_17 = {72 75 73 6b 69 6c 6c } //01 00  ruskill
		$a_00_18 = {68 74 74 70 73 70 72 65 61 64 } //01 00  httpspread
		$a_00_19 = {66 66 67 72 61 62 00 } //01 00 
		$a_00_20 = {69 65 67 72 61 62 00 } //00 00 
	condition:
		any of ($a_*)
 
}