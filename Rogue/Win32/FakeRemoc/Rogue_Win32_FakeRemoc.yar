
rule Rogue_Win32_FakeRemoc{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 6e 74 69 4d 61 6c 77 61 72 65 4d 61 73 74 65 72 90 01 08 2d 90 01 04 2d 90 01 04 2d 90 01 04 2d 90 01 0c 00 90 00 } //1
		$a_02_1 = {54 6f 74 61 6c 53 63 61 6e 43 6f 75 6e 74 90 02 06 49 6e 66 65 63 74 69 6f 6e 43 6f 75 6e 74 90 02 06 49 73 50 61 69 64 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Rogue_Win32_FakeRemoc_2{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //1 Nullsoft Install System
		$a_01_1 = {69 6e 73 74 73 2e 73 70 79 77 61 72 65 72 65 6d 6f 76 65 72 32 30 30 39 70 6c 75 73 2e 63 6f 6d 2f 3f 61 63 74 69 6f 6e } //1 insts.spywareremover2009plus.com/?action
		$a_01_2 = {53 70 79 77 61 72 65 52 65 6d 6f 76 65 72 32 30 30 39 20 69 73 20 62 65 69 6e 67 20 64 6f 77 6e 6c 6f 61 64 65 64 20 74 6f 20 50 43 2e 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Rogue_Win32_FakeRemoc_3{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 ff ff 00 00 0d 00 00 07 80 c3 } //1
		$a_03_1 = {be 1f 00 02 00 56 57 ff 75 e0 8d 4d e8 e8 90 01 04 85 c0 74 32 68 19 00 02 00 90 00 } //1
		$a_00_2 = {33 00 41 00 39 00 33 00 37 00 37 00 41 00 36 00 2d 00 42 00 45 00 37 00 46 00 2d 00 34 00 38 00 35 00 44 00 2d 00 39 00 30 00 38 00 43 00 2d 00 44 00 34 00 34 00 31 00 31 00 34 00 36 00 39 00 31 00 33 00 38 00 39 00 } //1 3A9377A6-BE7F-485D-908C-D44114691389
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Rogue_Win32_FakeRemoc_4{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 41 53 43 6f 6e 74 65 78 74 4d 65 6e 75 00 } //3
		$a_01_1 = {73 68 65 6c 6c 65 78 5c 43 6f 6e 74 65 78 74 4d 65 6e 75 48 61 6e 64 6c 65 72 73 5c 45 78 70 6c 6f 72 65 72 57 41 53 00 } //3 桳汥敬屸潃瑮硥䵴湥䡵湡汤牥屳硅汰牯牥䅗S
		$a_00_2 = {34 35 36 37 41 42 31 32 2d 45 44 45 44 2d 34 36 37 35 2d 41 46 31 30 2d 42 41 31 35 45 44 44 42 34 44 37 41 } //2 4567AB12-EDED-4675-AF10-BA15EDDB4D7A
		$a_00_3 = {49 73 50 61 69 64 50 72 6f 64 75 63 74 } //1 IsPaidProduct
		$a_00_4 = {44 6f 77 6e 6c 6f 61 64 50 72 6f 64 75 63 74 55 52 4c } //1 DownloadProductURL
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=8
 
}
rule Rogue_Win32_FakeRemoc_5{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 6e 74 69 53 70 79 77 61 72 65 4d 61 73 74 65 72 90 01 08 2d 90 01 04 2d 90 01 04 2d 90 01 04 2d 90 01 0c 00 90 00 } //10
		$a_00_1 = {5b 50 52 4f 44 55 43 54 5f 4e 41 4d 45 5d 00 00 5b 50 52 4f 44 55 43 54 5f 50 52 45 53 41 4c 45 5d 00 00 00 5b 57 45 42 53 49 54 45 5f 55 52 4c 5d 00 00 00 70 61 67 65 2e 68 74 6d 6c } //10
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1) >=21
 
}
rule Rogue_Win32_FakeRemoc_6{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR_EXT,41 00 41 00 09 00 00 "
		
	strings :
		$a_01_0 = {61 6e 74 69 6d 61 6c 77 61 72 65 67 75 61 72 64 2e 63 6f 6d } //5 antimalwareguard.com
		$a_01_1 = {61 6e 74 69 6d 61 6c 77 61 72 65 67 75 61 72 64 70 72 6f 2e 63 6f 6d } //5 antimalwareguardpro.com
		$a_01_2 = {41 6e 74 69 4d 61 6c 77 61 72 65 47 75 61 72 64 32 30 30 38 } //5 AntiMalwareGuard2008
		$a_01_3 = {58 50 20 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 } //10 XP Security Center
		$a_01_4 = {43 53 49 44 4c 5f 43 4f 4f 4b 49 45 53 } //10 CSIDL_COOKIES
		$a_01_5 = {43 53 49 44 4c 5f 41 50 50 44 41 54 41 } //10 CSIDL_APPDATA
		$a_01_6 = {43 53 49 44 4c 5f 41 44 4d 49 4e 54 4f 4f 4c 53 } //10 CSIDL_ADMINTOOLS
		$a_01_7 = {61 63 74 6e 5f 6f 72 64 65 72 5f 69 64 } //10 actn_order_id
		$a_01_8 = {61 63 74 6e 5f 70 61 73 73 77 6f 72 64 } //10 actn_password
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10) >=65
 
}
rule Rogue_Win32_FakeRemoc_7{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 6e 74 69 53 70 79 77 61 72 65 4d 61 73 74 65 72 90 01 08 2d 90 01 04 2d 90 01 04 2d 90 01 04 2d 90 01 0c 00 90 00 } //10
		$a_00_1 = {44 69 61 6c 65 72 00 00 64 69 61 6c 65 72 00 00 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6d 64 69 61 6c 33 32 2e 64 6c 6c 00 00 00 00 54 72 6f 6a 61 6e 00 00 74 72 6f 6a 61 6e 00 00 42 61 63 6b 64 6f 6f 72 00 00 00 00 62 61 63 6b 64 6f 6f 72 00 00 00 00 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 73 76 63 68 6f 73 74 2e 65 78 65 00 41 64 77 61 72 65 00 00 61 64 77 61 72 65 00 00 53 70 79 77 61 72 65 00 73 70 79 77 61 72 65 00 43 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 69 65 73 65 74 75 70 2e 64 6c 6c } //10
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
	condition:
		((#a_03_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1) >=21
 
}
rule Rogue_Win32_FakeRemoc_8{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {25 73 3d 7b 61 7d 26 25 73 3d 7b 6c 7d 26 25 73 3d 7b 66 7d 26 25 73 3d 7b 70 7d 26 25 73 3d 7b 61 64 64 74 7d 26 00 } //3
		$a_00_1 = {00 56 69 72 75 73 65 73 2e 62 64 74 00 7b 61 7d 00 7b 6c 7d 00 7b 66 7d 00 7b 70 7d 00 7b 61 64 64 74 7d 00 } //3 嘀物獵獥戮瑤笀絡笀絬笀給笀絰笀摡瑤}
		$a_01_2 = {00 53 74 61 74 69 73 74 69 63 61 6e 00 } //3
		$a_01_3 = {00 50 63 50 63 55 70 64 61 74 65 72 00 } //1
		$a_01_4 = {69 6e 64 65 72 4e 61 67 } //3 inderNag
		$a_01_5 = {00 43 56 69 72 75 73 52 6f 6c 6c 69 6e 67 44 6c 67 00 } //3 䌀楖畲剳汯楬杮汄g
		$a_00_6 = {00 56 69 72 75 73 65 73 2e 62 64 74 00 43 52 6f 6c 6c 69 6e 67 44 6c 67 00 } //3
		$a_01_7 = {3c 69 74 65 6d 20 6e 61 6d 65 3d 22 57 33 32 2e 53 70 79 62 6f 74 2e 41 56 45 4e 22 3e 69 73 20 61 20 77 6f 72 6d 20 } //1 <item name="W32.Spybot.AVEN">is a worm 
		$a_01_8 = {2e 20 54 68 65 20 75 72 6c 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 73 68 6f 77 73 20 48 61 72 64 63 6f 72 65 20 50 6f 72 6e 6f 67 72 61 70 68 69 63 20 70 61 67 65 73 2e } //1 . The url information shows Hardcore Pornographic pages.
		$a_01_9 = {53 79 6d 62 4f 53 2e 48 61 74 69 68 61 74 69 2e 41 22 3e 69 73 20 61 20 54 72 6f 6a 61 6e 20 68 6f 72 73 65 20 } //1 SymbOS.Hatihati.A">is a Trojan horse 
		$a_01_10 = {20 70 61 72 74 69 61 6c 6c 79 20 65 72 61 73 65 73 20 2e 77 6d 61 20 66 69 6c 65 73 20 6f 6e 20 74 68 65 20 63 6f 6d 70 72 6f 6d } //1  partially erases .wma files on the comprom
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_00_6  & 1)*3+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=10
 
}
rule Rogue_Win32_FakeRemoc_9{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {50 52 4f 44 5f 43 4f 4f 4b 49 45 5f 55 52 4c 3d 63 6c 65 61 6e 65 72 32 30 30 39 70 72 6f 2e 63 6f 6d } //1 PROD_COOKIE_URL=cleaner2009pro.com
		$a_01_1 = {41 49 44 7d 5c 5c 64 61 74 61 2e 69 6e 69 5c 71 69 70 5c } //1 AID}\\data.ini\qip\
		$a_01_2 = {53 54 41 54 5f 55 52 4c 3d 68 74 74 70 3a 2f 2f 69 6e 73 2e 71 75 69 63 6b 69 6e 73 74 61 6c 6c 70 61 63 6b 2e 63 6f 6d 2f 3f 61 63 74 69 6f 6e 3d 7b 41 43 54 49 4f 4e 5f 49 44 7d 26 71 61 64 3d 63 6c 6e 26 71 6c 64 3d 7b 4c 49 44 7d 26 71 61 66 3d 7b 41 46 46 49 44 7d 26 63 6e 74 3d 7b 43 4e 54 7d 26 6c 6e 67 3d 7b 4c 4e 47 7d 26 6f 72 64 65 72 5f 69 64 3d 7b 4f 49 44 7d 26 6c 70 3d 7b 4c 50 7d 26 61 64 64 74 3d 7b 41 44 44 54 7d 26 70 63 5f 69 64 3d 7b 50 43 5f 49 44 7d 26 65 72 72 3d 7b 45 52 52 7d 26 61 62 62 72 3d 7b 41 42 42 52 7d } //1 STAT_URL=http://ins.quickinstallpack.com/?action={ACTION_ID}&qad=cln&qld={LID}&qaf={AFFID}&cnt={CNT}&lng={LNG}&order_id={OID}&lp={LP}&addt={ADDT}&pc_id={PC_ID}&err={ERR}&abbr={ABBR}
		$a_01_3 = {53 45 54 5f 50 41 59 50 41 47 45 5f 55 52 4c 3d 68 74 74 70 3a 2f 2f 71 75 69 63 6b 69 6e 73 74 61 6c 6c 70 61 63 6b 2e 63 6f 6d 2f 71 75 69 63 6b 69 6e 73 74 61 6c 6c 2f 6f 72 64 65 72 2e 70 68 70 3f 71 61 64 3d 63 6c 6e 26 71 6c 64 3d 7b 4c 49 44 7d 26 71 61 66 3d 7b 41 46 46 49 44 7d 26 6c 70 3d 7b 4c 50 7d 26 61 64 64 74 3d 7b 41 44 44 54 7d 26 6e 69 64 3d 7b 4e 49 44 7d 26 65 72 72 3d 7b 45 52 52 7d } //1 SET_PAYPAGE_URL=http://quickinstallpack.com/quickinstall/order.php?qad=cln&qld={LID}&qaf={AFFID}&lp={LP}&addt={ADDT}&nid={NID}&err={ERR}
		$a_01_4 = {53 54 41 54 5f 55 52 4c 3d 68 74 74 70 3a 2f 2f 75 6c 6f 67 2e 63 6c 65 61 6e 65 72 32 30 30 39 70 72 6f 2e 63 6f 6d 2f 3f 61 63 74 69 6f 6e 3d 7b 41 43 54 49 4f 4e 5f 49 44 7d 26 61 3d 7b 41 49 44 7d 26 6c 3d 7b 4c 49 44 7d 26 66 3d 7b 41 46 46 49 44 7d 26 63 6e 74 3d 7b 43 4e 54 7d 26 6c 6e 67 3d 7b 4c 4e 47 7d 26 6f 72 64 65 72 5f 69 64 3d 7b 4f 49 44 7d 26 6c 70 3d 7b 4c 50 7d 26 61 64 64 74 3d 7b 41 44 44 54 7d 26 70 63 5f 69 64 3d 7b 50 43 5f 49 44 7d 26 65 72 72 3d 7b 45 52 52 7d 26 61 62 62 72 3d 7b 41 42 42 52 7d } //1 STAT_URL=http://ulog.cleaner2009pro.com/?action={ACTION_ID}&a={AID}&l={LID}&f={AFFID}&cnt={CNT}&lng={LNG}&order_id={OID}&lp={LP}&addt={ADDT}&pc_id={PC_ID}&err={ERR}&abbr={ABBR}
		$a_01_5 = {53 54 41 54 5f 55 52 4c 3d 68 74 74 70 3a 2f 2f 69 6e 73 66 2e 71 75 69 63 6b 69 6e 73 74 61 6c 6c 70 61 63 6b 2e 63 6f 6d 2f 3f 61 63 74 69 6f 6e 3d 7b 41 43 54 49 4f 4e 5f 49 44 7d 26 71 61 64 3d 63 6c 6e 26 71 6c 64 3d 7b 4c 49 44 7d 26 71 61 66 3d 7b 41 46 46 49 44 7d 26 63 6e 74 3d 7b 43 4e 54 7d 26 6c 6e 67 3d 7b 4c 4e 47 7d 26 6f 72 64 65 72 5f 69 64 3d 7b 4f 49 44 7d 26 6c 70 3d 7b 4c 50 7d 26 61 64 64 74 3d 7b 41 44 44 54 7d 26 70 63 5f 69 64 3d 7b 50 43 5f 49 44 7d 26 65 72 72 3d 7b 45 52 52 7d 26 61 62 62 72 3d 7b 41 42 42 52 7d } //1 STAT_URL=http://insf.quickinstallpack.com/?action={ACTION_ID}&qad=cln&qld={LID}&qaf={AFFID}&cnt={CNT}&lng={LNG}&order_id={OID}&lp={LP}&addt={ADDT}&pc_id={PC_ID}&err={ERR}&abbr={ABBR}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Rogue_Win32_FakeRemoc_10{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 53 65 74 43 6f 6f 6b 69 65 41 00 } //10
		$a_01_1 = {75 72 6c 6d 6f 6e 2e 64 6c 6c 00 } //10
		$a_01_2 = {73 65 63 5f 6d 75 74 65 78 00 } //2 敳彣畭整x
		$a_01_3 = {73 63 6e 73 5f 74 69 6d 65 00 } //2 捳獮瑟浩e
		$a_01_4 = {41 46 46 49 44 3d 25 73 } //1 AFFID=%s
		$a_01_5 = {50 61 79 6d 65 6e 74 50 61 67 65 5f 52 65 75 73 65 } //1 PaymentPage_Reuse
		$a_01_6 = {72 65 6c 65 61 73 65 5c 53 45 43 2e 70 64 62 00 } //1 敲敬獡履䕓⹃摰b
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=25
 
}
rule Rogue_Win32_FakeRemoc_11{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR,24 00 23 00 07 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 41 6e 74 69 4d 61 6c 77 61 72 65 47 75 61 72 64 } //10 C:\Program Files\AntiMalwareGuard
		$a_01_1 = {61 6e 74 69 6d 61 6c 77 61 72 65 67 75 61 72 64 2e 63 6f 6d } //10 antimalwareguard.com
		$a_01_2 = {61 6d 67 2e 65 78 65 } //10 amg.exe
		$a_01_3 = {61 63 74 6e 5f 6f 72 64 65 72 5f 69 64 } //5 actn_order_id
		$a_01_4 = {6d 61 6c 77 61 72 65 63 72 61 73 68 70 72 6f 2e 63 6f 6d } //1 malwarecrashpro.com
		$a_01_5 = {41 6e 74 69 76 69 72 78 70 30 38 5f 72 65 67 } //1 Antivirxp08_reg
		$a_01_6 = {41 6e 74 69 53 70 79 77 61 72 65 4d 61 73 74 65 72 } //1 AntiSpywareMaster
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=35
 
}
rule Rogue_Win32_FakeRemoc_12{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR,05 00 05 00 09 00 00 "
		
	strings :
		$a_01_0 = {00 00 73 65 63 5f 6d 75 74 65 78 00 00 } //2
		$a_01_1 = {74 00 65 00 78 00 74 00 5f 00 62 00 74 00 6e 00 5f 00 73 00 70 00 61 00 63 00 65 00 } //1 text_btn_space
		$a_01_2 = {72 65 6d 69 6e 64 65 72 5f 6d 75 74 65 78 } //1 reminder_mutex
		$a_01_3 = {69 00 6d 00 67 00 5f 00 73 00 79 00 73 00 5f 00 69 00 63 00 6f 00 6e 00 } //1 img_sys_icon
		$a_01_4 = {00 5c 53 45 43 5c 62 73 74 61 74 65 2e 64 61 74 00 } //1
		$a_01_5 = {53 74 61 74 69 73 74 69 63 61 6e 00 70 63 5f 69 64 3d 25 75 } //1 瑓瑡獩楴慣n捰楟㵤甥
		$a_01_6 = {00 41 63 74 69 76 61 74 69 6f 6e 44 6c 67 00 } //1
		$a_01_7 = {72 65 6c 65 61 73 65 5c 53 45 43 2e 70 64 62 } //1 release\SEC.pdb
		$a_01_8 = {6e 61 63 74 69 6f 6e 3d 25 64 26 } //1 naction=%d&
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=5
 
}
rule Rogue_Win32_FakeRemoc_13{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR,07 00 07 00 0a 00 00 "
		
	strings :
		$a_01_0 = {50 65 72 73 6f 6e 61 6c 53 70 79 00 } //2 敐獲湯污灓y
		$a_01_1 = {52 65 61 6c 74 69 6d 65 41 6c 65 72 74 73 00 00 5a 6f 6d 62 69 65 54 68 72 65 61 74 73 } //1
		$a_01_2 = {63 6f 6f 6b 69 65 00 00 72 65 67 76 61 6c 75 65 } //1
		$a_01_3 = {41 75 74 6f 52 75 6e 44 6c 67 00 } //1
		$a_01_4 = {41 6c 65 72 74 44 65 73 63 72 69 70 74 69 6f 6e 00 } //1
		$a_01_5 = {00 69 6e 73 74 61 6e 74 73 63 61 6e 00 } //1
		$a_01_6 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 54 65 72 6d 69 6e 61 6c 20 53 65 72 76 65 72 5c 49 6e 73 74 61 6c 6c 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 } //1 CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows
		$a_01_7 = {72 65 76 69 76 65 64 00 6c 65 76 65 6c } //1
		$a_01_8 = {64 65 6c 65 74 65 64 5f 61 66 74 65 72 5f 72 65 62 6f 6f 74 } //1 deleted_after_reboot
		$a_01_9 = {53 63 61 6e 52 65 70 6f 72 74 73 00 52 65 70 6f 72 74 } //1 捓湡敒潰瑲s敒潰瑲
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=7
 
}
rule Rogue_Win32_FakeRemoc_14{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR,06 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {50 61 79 6d 65 6e 74 50 61 67 65 5f 52 65 75 73 65 5f 33 35 44 35 34 31 32 45 38 35 35 43 34 30 63 34 38 35 34 44 2d 35 42 31 35 35 36 35 43 39 35 31 42 00 } //3 慐浹湥側条彥敒獵彥㔳㕄ㄴ䔲㔸䌵〴㑣㔸䐴㔭ㅂ㔵㔶㥃ㄵB
		$a_01_1 = {43 6c 65 61 6e 65 72 32 30 30 39 5c } //2 Cleaner2009\
		$a_01_2 = {46 69 72 73 74 41 63 74 69 76 61 74 69 6f 6e 41 74 74 65 6d 70 74 54 69 6d 65 00 } //1
		$a_01_3 = {52 67 64 55 70 64 61 74 65 72 00 } //2
		$a_01_4 = {53 70 79 77 61 72 65 52 65 6d 6f 76 65 72 32 30 30 39 } //1 SpywareRemover2009
		$a_01_5 = {2f 61 64 76 2f 6f 72 64 65 72 2f 3f 61 62 62 72 3d } //2 /adv/order/?abbr=
		$a_01_6 = {61 63 74 6e 5f 6f 72 64 65 72 5f 69 64 00 } //1 捡湴潟摲牥楟d
		$a_01_7 = {41 42 42 52 3d 44 4f 57 4e 4c 49 4e 4b 3d 44 4f 4d 41 49 4e 4e 41 4d 45 3d 50 52 4f 44 55 43 54 4e 41 4d 45 23 4f 57 4e 45 52 4e 41 4d 45 23 45 4d 41 49 4c 23 4f 52 44 45 52 49 44 23 50 41 53 53 57 4f 52 44 } //3 ABBR=DOWNLINK=DOMAINNAME=PRODUCTNAME#OWNERNAME#EMAIL#ORDERID#PASSWORD
		$a_01_8 = {3e 4f 72 64 65 72 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 3a } //1 >Order information:
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*3+(#a_01_8  & 1)*1) >=6
 
}
rule Rogue_Win32_FakeRemoc_15{
	meta:
		description = "Rogue:Win32/FakeRemoc,SIGNATURE_TYPE_PEHSTR,20 00 20 00 0e 00 00 "
		
	strings :
		$a_01_0 = {50 65 72 73 6f 6e 61 6c 41 6e 74 69 53 70 79 00 } //10 敐獲湯污湁楴灓y
		$a_01_1 = {00 50 41 53 5f 53 48 55 54 44 4f 57 4e 00 } //10 倀十卟啈䑔坏N
		$a_01_2 = {00 50 41 53 2e 65 78 65 00 } //10
		$a_01_3 = {70 65 72 73 6f 6e 61 6c 61 6e 74 69 73 70 79 2e 63 6f 6d } //10 personalantispy.com
		$a_01_4 = {70 61 73 69 20 3d 20 75 6e 69 6e 73 74 61 6c 6c } //10 pasi = uninstall
		$a_01_5 = {48 61 6e 64 6c 65 72 73 5c 45 78 70 6c 6f 72 65 72 55 50 41 53 } //10 Handlers\ExplorerUPAS
		$a_01_6 = {75 70 61 73 68 65 6c 6c 65 78 74 2e 57 41 53 } //10 upashellext.WAS
		$a_01_7 = {31 39 32 34 46 41 32 39 2d 39 37 34 30 2d 34 46 36 42 2d 41 36 38 33 2d 39 30 46 42 34 32 46 43 31 32 33 37 } //1 1924FA29-9740-4F6B-A683-90FB42FC1237
		$a_01_8 = {35 43 41 42 36 41 37 39 2d 37 37 31 30 2d 34 30 35 61 2d 39 42 30 38 2d 41 31 33 45 39 30 38 35 33 34 45 39 } //1 5CAB6A79-7710-405a-9B08-A13E908534E9
		$a_01_9 = {49 6e 73 74 61 6c 6c 43 6f 6f 6b 69 65 46 6f 72 6d 61 74 } //1 InstallCookieFormat
		$a_01_10 = {44 65 66 61 75 6c 74 42 4e 55 52 4c } //1 DefaultBNURL
		$a_01_11 = {53 68 75 74 64 6f 77 6e 57 69 6e 64 6f 77 4d 65 73 73 61 67 65 } //1 ShutdownWindowMessage
		$a_01_12 = {41 70 70 47 6c 6f 62 61 6c 4d 75 74 65 78 4e 61 6d 65 } //1 AppGlobalMutexName
		$a_01_13 = {53 68 65 6c 6c 48 6f 6f 6b 4e 61 6d 65 } //1 ShellHookName
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1) >=32
 
}