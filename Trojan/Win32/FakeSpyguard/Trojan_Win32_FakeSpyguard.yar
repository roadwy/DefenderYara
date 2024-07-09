
rule Trojan_Win32_FakeSpyguard{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 72 61 63 6b 5f 69 64 3d 25 64 00 } //2 牴捡彫摩┽d
		$a_01_1 = {73 76 68 6f 73 74 2e 65 78 65 00 } //1
		$a_01_2 = {43 54 45 4d 4f 4e 2e 45 58 45 00 } //1
		$a_01_3 = {53 70 79 77 61 72 65 20 47 75 61 72 64 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule Trojan_Win32_FakeSpyguard_2{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 72 6f 74 65 63 74 5c } //3 \Application Data\Microsoft\Protect\
		$a_01_1 = {73 68 6c 63 6f 6e 66 2e 64 61 74 } //1 shlconf.dat
		$a_01_2 = {72 6d 6c 69 73 74 2e 64 61 74 } //1 rmlist.dat
		$a_01_3 = {53 65 63 75 72 69 74 79 33 32 5f 77 69 6e } //1 Security32_win
		$a_01_4 = {72 74 69 6d 65 2e 64 61 74 } //1 rtime.dat
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_FakeSpyguard_3{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 43 33 32 58 5f 4d 75 74 65 78 } //3 SC32X_Mutex
		$a_01_1 = {67 6f 73 67 32 30 30 38 2e 63 6f 6d } //1 gosg2008.com
		$a_00_2 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 72 65 70 6f 72 74 73 20 74 68 61 74 20 27 53 70 79 77 61 72 65 20 47 75 61 72 64 } //1 Windows Security Center reports that 'Spyware Guard
		$a_01_3 = {43 6f 6f 6c 54 72 61 79 49 63 6f 6e 31 42 61 6c 6c 6f 6f 6e 48 69 6e 74 43 6c 69 63 6b } //1 CoolTrayIcon1BalloonHintClick
		$a_01_4 = {2f 3f 74 72 61 63 6b 5f 69 64 3d 25 64 } //1 /?track_id=%d
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule Trojan_Win32_FakeSpyguard_4{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {57 69 6e 53 65 63 75 72 69 74 79 5f 78 38 36 00 } //1 楗卮捥牵瑩役㡸6
		$a_00_1 = {53 70 79 77 61 72 65 20 47 75 61 72 64 20 32 30 30 38 00 } //1
		$a_00_2 = {73 70 79 77 61 72 65 67 75 61 72 64 2e 65 78 65 00 } //1
		$a_03_3 = {6a ff 68 01 00 1f 00 e8 ?? ?? ?? ?? 85 c0 75 ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 85 c0 77 ?? 6a 00 } //3
		$a_03_4 = {68 dc 05 00 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ?? 6a 00 6a 00 68 03 04 00 00 50 e8 ?? ?? ?? ?? eb } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*3+(#a_03_4  & 1)*3) >=4
 
}
rule Trojan_Win32_FakeSpyguard_5{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_02_0 = {5c 4d 69 63 72 6f 73 6f 66 74 20 (41|50) 44 61 74 61 5c } //2
		$a_00_1 = {53 6d 61 72 74 20 50 72 6f 74 65 63 74 6f 72 00 } //2 浓牡⁴牐瑯捥潴r
		$a_00_2 = {50 65 72 73 6f 6e 61 6c 20 50 72 6f 74 65 63 74 6f 72 00 } //2
		$a_00_3 = {44 6f 77 6e 6c 6f 61 64 65 72 2e 4d 44 57 5c 54 72 6f 6a 61 6e } //1 Downloader.MDW\Trojan
		$a_00_4 = {56 69 72 74 75 6d 6f 6e 64 65 5c 54 72 6f 6a 61 6e } //1 Virtumonde\Trojan
		$a_00_5 = {52 65 62 6f 6f 74 65 72 2e 4a 5c 54 72 6f 6a 61 6e } //1 Rebooter.J\Trojan
		$a_00_6 = {53 69 73 74 65 6d 4b 65 79 00 } //1 楓瑳浥敋y
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}
rule Trojan_Win32_FakeSpyguard_6{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 65 63 75 72 69 74 79 33 32 5f 77 69 6e } //1 Security32_win
		$a_00_1 = {2f 3f 74 72 61 63 6b 5f 69 64 3d 25 64 } //1 /?track_id=%d
		$a_02_2 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 72 65 70 6f 72 74 73 20 74 68 61 74 20 [0-20] 20 69 73 20 69 6e 61 63 74 69 76 65 2e } //1
		$a_00_3 = {53 43 33 32 58 5f 4d 75 74 65 78 } //1 SC32X_Mutex
		$a_00_4 = {4e 6f 74 65 3a 20 57 69 6e 64 6f 77 73 20 68 61 73 20 64 65 74 65 63 74 65 64 20 61 6e 20 75 6e 72 65 67 69 73 74 65 72 65 64 20 76 65 72 73 69 6f 6e 20 6f 66 20 27 } //1 Note: Windows has detected an unregistered version of '
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}
rule Trojan_Win32_FakeSpyguard_7{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_00_0 = {2f 73 65 74 75 70 2e 70 68 70 3f 74 72 61 63 6b 5f 69 64 3d 25 64 } //2 /setup.php?track_id=%d
		$a_00_1 = {2f 3f 74 72 61 63 6b 5f 69 64 3d 25 64 } //1 /?track_id=%d
		$a_00_2 = {73 76 63 68 6f 73 32 2e 65 78 65 00 } //1 癳档獯⸲硥e
		$a_00_3 = {73 76 63 68 6f 73 2e 65 78 65 00 } //1
		$a_00_4 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c } //1 \Application Data\Microsoft\
		$a_00_5 = {5c 4d 69 63 72 6f 73 6f 66 74 20 50 72 69 76 61 74 65 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c } //1 \Microsoft Private Data\Microsoft\
		$a_02_6 = {5c 4d 69 63 72 6f 73 6f 66 74 20 (41|50) 44 61 74 61 5c } //1
		$a_00_7 = {44 6f 77 6e 6c 6f 61 64 65 72 2e 4d 44 57 5c 54 72 6f 6a 61 6e } //1 Downloader.MDW\Trojan
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1+(#a_00_7  & 1)*1) >=4
 
}
rule Trojan_Win32_FakeSpyguard_8{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_01_0 = {45 72 72 6f 72 20 34 30 34 20 4e 6f 74 20 46 6f 75 6e 64 2e } //1 Error 404 Not Found.
		$a_01_1 = {46 61 74 61 6c 20 65 72 72 6f 72 21 } //1 Fatal error!
		$a_01_2 = {2f 73 65 74 75 70 2e 70 68 70 3f } //1 /setup.php?
		$a_01_3 = {2f 69 6e 73 74 61 6c 6c 2f 3f } //1 /install/?
		$a_01_4 = {74 72 61 63 6b 5f 69 64 3d 25 64 } //1 track_id=%d
		$a_00_5 = {43 54 45 4d 4f 4e 2e 45 58 45 00 } //1
		$a_00_6 = {53 4f 46 54 57 41 52 45 5c 53 70 79 77 61 72 65 20 47 75 61 72 64 } //1 SOFTWARE\Spyware Guard
		$a_00_7 = {54 68 69 73 20 77 69 6c 6c 20 69 6e 73 74 61 6c 6c 20 74 68 65 20 74 72 69 61 6c 20 76 65 72 73 69 6f 6e 20 6f 66 20 53 70 79 77 61 72 65 20 47 75 61 72 64 20 32 30 } //1 This will install the trial version of Spyware Guard 20
		$a_02_8 = {53 70 79 77 61 72 65 20 47 75 61 72 64 20 32 30 [0-02] 20 69 6e 73 74 61 6c 6c 61 74 69 6f 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_02_8  & 1)*1) >=8
 
}
rule Trojan_Win32_FakeSpyguard_9{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 65 63 75 72 69 74 79 33 32 5f 77 69 6e 00 00 53 70 79 77 61 72 65 20 47 75 61 72 64 20 32 30 30 38 } //1
		$a_01_1 = {50 72 6f 6a 65 63 74 31 2e 64 6c 6c 00 53 65 74 48 6f 6f 6b } //1 牐橯捥ㅴ搮汬匀瑥潈歯
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_FakeSpyguard_10{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2a 7c 64 6f 6d 61 69 6e 7c 2a } //2 *|domain|*
		$a_01_1 = {68 74 74 70 3a 2f 2f 25 64 6f 6d 61 69 6e 25 2f 63 6f 6e 74 65 6e 74 2e 70 68 70 3f 73 65 5f 69 64 3d 25 64 26 71 3d 25 73 26 70 61 67 65 3d 25 73 26 75 61 3d 25 73 26 61 6c 3d 25 73 26 61 66 66 5f 69 64 3d 25 73 26 73 75 62 5f 69 64 3d 25 73 } //1 http://%domain%/content.php?se_id=%d&q=%s&page=%s&ua=%s&al=%s&aff_id=%s&sub_id=%s
		$a_01_2 = {68 74 74 70 3a 2f 2f 25 64 6f 6d 61 69 6e 25 2f 63 6f 6e 66 69 67 2e 70 68 70 } //1 http://%domain%/config.php
		$a_01_3 = {68 74 74 70 3a 2f 2f 25 64 6f 6d 61 69 6e 25 2f 75 70 64 61 74 65 2e 70 68 70 } //1 http://%domain%/update.php
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_FakeSpyguard_11{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 50 47 75 61 72 64 4d 74 78 } //1 SPGuardMtx
		$a_01_1 = {68 74 74 70 3a 2f 2f 67 6f 73 67 64 2e 63 6f 6d } //1 http://gosgd.com
		$a_01_2 = {68 74 74 70 3a 2f 2f 67 6f 73 67 64 32 2e 63 6f 6d } //1 http://gosgd2.com
		$a_01_3 = {53 70 79 77 61 72 65 20 47 75 61 72 64 20 32 30 30 38 } //1 Spyware Guard 2008
		$a_01_4 = {57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 } //1 Windows Security Center
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //1 SOFTWARE\Borland\Delphi\RTL
		$a_01_6 = {5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 72 6f 74 65 63 74 5c } //1 \Application Data\Microsoft\Protect\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
rule Trojan_Win32_FakeSpyguard_12{
	meta:
		description = "Trojan:Win32/FakeSpyguard,SIGNATURE_TYPE_PEHSTR,06 00 04 00 09 00 00 "
		
	strings :
		$a_01_0 = {2f 62 75 79 2e 68 74 6d 6c 3f 74 72 61 63 6b 5f 69 64 3d } //1 /buy.html?track_id=
		$a_01_1 = {2f 6b 65 79 2f 3f 6b 65 79 3d 25 73 26 65 6d 61 69 6c 3d 25 73 } //1 /key/?key=%s&email=%s
		$a_01_2 = {61 72 65 70 6f 72 74 63 6f 75 6e 74 00 } //1
		$a_01_3 = {54 66 6d 57 61 72 6e 69 6e 67 33 41 74 74 61 63 6b } //1 TfmWarning3Attack
		$a_01_4 = {41 67 6f 62 6f 74 20 76 69 61 20 57 65 62 44 41 56 20 65 78 70 6c 6f 69 74 } //1 Agobot via WebDAV exploit
		$a_01_5 = {44 6f 20 79 6f 75 20 77 61 6e 74 20 61 63 74 69 76 61 74 65 20 74 68 65 20 61 6e 74 69 76 69 72 75 73 20 73 6f 66 74 77 61 72 65 3f } //1 Do you want activate the antivirus software?
		$a_01_6 = {4c 6f 77 00 ff ff ff ff 04 00 00 00 48 69 67 68 00 00 00 00 ff ff ff ff 08 00 00 00 43 72 69 74 69 63 61 6c } //2
		$a_01_7 = {2f 61 63 74 69 76 61 74 65 2f 3f 6b 65 79 3d 25 73 26 65 6d 61 69 6c 3d 25 73 26 74 72 61 63 6b 5f 69 64 3d 25 64 26 74 69 6d 65 3d 25 73 } //2 /activate/?key=%s&email=%s&track_id=%d&time=%s
		$a_01_8 = {2f 75 70 64 61 74 65 2f 3f 61 63 74 69 6f 6e 3d 67 65 74 5f 62 61 73 65 26 62 61 73 65 3d 31 } //2 /update/?action=get_base&base=1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2) >=4
 
}