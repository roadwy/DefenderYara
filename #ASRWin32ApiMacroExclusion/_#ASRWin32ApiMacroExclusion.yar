
rule _#ASRWin32ApiMacroExclusion{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {50 61 6c 69 73 61 64 65 } //1 Palisade
		$a_00_1 = {44 54 4f 4f 4c 53 38 5f 78 38 36 2e 58 4c 4c } //1 DTOOLS8_x86.XLL
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule _#ASRWin32ApiMacroExclusion_2{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 4f 50 20 52 65 74 75 72 6e 2e 78 6c 73 6d } //2 SOP Return.xlsm
		$a_00_1 = {53 4f 50 20 44 61 74 61 20 42 41 43 4b 55 50 2e 78 6c 73 6d } //2 SOP Data BACKUP.xlsm
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_3{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {61 70 70 6c 69 63 61 74 69 6f 6e 2e 72 75 6e 28 22 70 69 70 75 74 76 61 6c 22 } //2 application.run("piputval"
		$a_00_1 = {70 69 65 78 74 69 6d 65 76 61 6c } //2 piextimeval
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_4{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 44 50 57 2d 41 70 70 73 5c } //5 C:\Program Files (x86)\DPW-Apps\
		$a_01_1 = {70 61 74 68 6c 69 6e 65 } //5 pathline
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}
rule _#ASRWin32ApiMacroExclusion_5{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 4c 42 32 44 41 54 41 28 29 } //2 Sub LB2DATA()
		$a_00_1 = {53 75 62 20 54 54 54 53 45 4c 45 43 54 49 4f 4e 28 29 } //2 Sub TTTSELECTION()
		$a_00_2 = {53 75 62 20 70 74 64 53 45 4c 45 43 54 49 4f 4e 28 29 } //2 Sub ptdSELECTION()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_6{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 6d 64 66 2d 78 6c 70 61 67 65 73 2e 63 6f 6d } //1 www.mdf-xlpages.com
		$a_00_1 = {77 77 77 2e 65 78 63 65 6c 61 62 6f 2e 6e 65 74 } //1 www.excelabo.net
		$a_00_2 = {68 74 74 70 3a 2f 2f 65 78 63 65 6c 2d 6d 61 6c 69 6e 2e 63 6f 6d } //1 http://excel-malin.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_7{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 4e 6f 74 65 73 22 29 2e 41 63 74 69 76 61 74 65 } //2 ActiveWorkbook.Worksheets("Notes").Activate
		$a_00_1 = {43 61 6c 6c 20 4a 72 6e 6c 53 68 65 65 74 5f 53 65 6c 65 63 74 } //2 Call JrnlSheet_Select
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_8{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {42 4f 4d 20 55 70 6c 6f 61 64 2e 78 6c 73 78 } //2 BOM Upload.xlsx
		$a_00_1 = {4d 73 67 42 6f 78 20 22 54 68 65 20 42 4f 4d 20 46 69 6c 65 20 68 61 73 20 62 65 65 6e 20 73 61 76 65 64 20 74 6f 20 22 } //2 MsgBox "The BOM File has been saved to "
		$a_00_2 = {53 75 62 20 42 4f 4d 5f 55 70 6c 6f 61 64 28 29 } //1 Sub BOM_Upload()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_9{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 56 65 72 6b 65 74 74 65 6e 5f 47 28 29 } //2 Public Sub Verketten_G()
		$a_00_1 = {53 75 62 20 53 41 50 5f 49 6d 70 6f 72 74 47 5f 45 72 7a 65 75 67 65 6e 28 29 } //2 Sub SAP_ImportG_Erzeugen()
		$a_00_2 = {53 75 62 20 5a 65 69 6c 65 45 69 6e 66 75 67 65 6e 5f 47 28 29 } //2 Sub ZeileEinfugen_G()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_10{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6e 61 6d 65 3d 22 61 73 61 70 75 74 69 6c 69 74 69 65 73 72 69 62 62 6f 6e 22 } //2 name="asaputilitiesribbon"
		$a_00_1 = {64 65 73 63 72 69 70 74 69 6f 6e 3d 22 72 69 62 62 6f 6e 20 61 6e 64 20 68 61 6e 64 6c 65 72 20 66 6f 72 20 61 73 61 70 20 75 74 69 6c 69 74 69 65 73 22 } //2 description="ribbon and handler for asap utilities"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}
rule _#ASRWin32ApiMacroExclusion_11{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 a9 20 22 20 26 20 59 65 61 72 28 4e 6f 77 29 20 26 20 22 2c 20 4d 55 46 47 20 42 61 6e 6b 2e 20 20 41 6c 6c 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2e } //10
		$a_01_1 = {43 49 51 54 69 63 6b 65 72 } //10 CIQTicker
		$a_01_2 = {52 41 54 6f 67 67 6c 65 50 46 } //10 RATogglePF
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule _#ASRWin32ApiMacroExclusion_12{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 65 74 73 28 22 50 42 52 5f 54 65 6d 70 6c 61 74 65 22 29 2e 53 65 6c 65 63 74 } //2 Sheets("PBR_Template").Select
		$a_00_1 = {53 75 62 20 65 78 70 6f 5f 63 6c 6f 73 65 50 42 52 28 29 } //2 Sub expo_closePBR()
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 53 70 6c 69 74 73 5f 46 4d 54 5f 31 28 29 } //2 Private Sub Splits_FMT_1()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_13{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 42 45 78 31 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 42 45 78 41 6e 61 6c 79 7a 65 72 2e 78 6c 61 21 47 65 74 42 45 78 22 29 } //2 Set BEx1 = Application.Run("BExAnalyzer.xla!GetBEx")
		$a_00_1 = {49 66 20 49 6e 53 74 72 28 6c 4e 61 6d 65 2e 4e 61 6d 65 2c 20 22 42 45 78 22 29 } //2 If InStr(lName.Name, "BEx")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_14{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 6f 66 74 77 61 72 65 5c 68 61 76 65 72 5c 64 6c 78 6d 65 6e 75 } //2 software\haver\dlxmenu
		$a_00_1 = {73 6f 66 74 77 61 72 65 5c 68 61 76 65 72 5c 64 6c 78 72 61 6e 67 65 72 } //2 software\haver\dlxranger
		$a_00_2 = {73 6f 66 74 77 61 72 65 5c 68 61 76 65 72 5c 65 78 63 65 6c 64 61 74 65 66 69 72 73 74 } //2 software\haver\exceldatefirst
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_15{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 50 6f 70 50 65 74 65 44 65 76 50 77 64 } //2 Public Sub PopPeteDevPwd
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 54 6f 67 67 6c 65 50 72 6f 64 56 65 72 73 69 6f 6e } //2 Public Sub ToggleProdVersion
		$a_00_2 = {50 75 62 6c 69 63 20 53 75 62 20 50 6f 70 50 65 74 65 42 6c 61 63 6b 50 77 64 } //2 Public Sub PopPeteBlackPwd
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_16{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 53 79 73 43 66 67 53 68 74 28 29 } //2 Public Function SysCfgSht()
		$a_00_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 44 64 43 66 67 53 68 74 28 29 } //2 Public Function DdCfgSht()
		$a_00_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 44 4d 61 73 74 53 68 74 28 29 } //2 Public Function DMastSht()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_17{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 53 42 43 6e 65 74 43 68 65 63 6b 2e 56 61 6c 75 65 } //2 HSBCnetCheck.Value
		$a_00_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 50 72 6f 74 65 63 74 20 28 22 61 62 65 72 6e 6f 77 61 79 22 29 } //2 ActiveSheet.Protect ("abernoway")
		$a_00_2 = {41 63 74 69 76 65 53 68 65 65 74 2e 4e 61 6d 65 20 3d 20 22 57 50 53 53 61 6c 61 72 79 22 } //2 ActiveSheet.Name = "WPSSalary"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_18{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {45 72 65 69 67 6e 69 73 73 65 20 64 65 61 6b 74 69 76 69 65 72 65 6e } //2 Ereignisse deaktivieren
		$a_00_1 = {42 69 6c 64 73 63 68 69 72 6d 61 6b 74 75 61 6c 69 73 69 65 72 75 6e 67 20 64 65 61 6b 74 69 76 69 65 72 65 6e } //2 Bildschirmaktualisierung deaktivieren
		$a_00_2 = {46 65 68 6c 65 72 62 65 68 61 6e 64 6c 75 6e 67 20 65 69 6e 6c 65 69 74 65 6e } //2 Fehlerbehandlung einleiten
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_19{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6e 6e 5f 63 61 73 65 73 2e 43 6c 6f 73 65 3a 20 53 65 74 20 63 6e 6e 5f 63 61 73 65 73 20 3d 20 4e 6f 74 68 69 6e 67 } //2 cnn_cases.Close: Set cnn_cases = Nothing
		$a_00_1 = {46 75 6e 63 74 69 6f 6e 20 46 54 4e 53 41 5f 49 6e 6c 69 6e 65 } //2 Function FTNSA_Inline
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 63 6d 62 59 65 61 72 5f 4b 65 79 44 6f 77 6e } //2 Private Sub cmbYear_KeyDown
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_20{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 6e 65 78 61 72 28 29 } //2 Sub Anexar()
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 41 6e 65 78 61 72 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 } //2 Attribute Anexar.VB_ProcData.VB_Invoke_Func
		$a_00_2 = {57 69 6e 64 6f 77 73 28 22 53 49 4f 5f 56 61 6c 6c 65 73 2e 78 6c 73 22 29 2e 41 63 74 69 76 61 74 65 } //2 Windows("SIO_Valles.xls").Activate
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_21{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 6f 48 6f 6d 65 54 6d 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub cboHomeTm_Change()
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 78 43 61 72 42 6b 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub cbxCarBk_Change()
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 6f 4c 6f 61 6e 54 6d 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub cboLoanTm_Change()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_22{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {45 69 6e 70 61 72 6b 65 6e 20 4d 61 6b 72 6f } //2 Einparken Makro
		$a_00_1 = {4d 61 6b 72 6f 20 45 44 56 2d 4e 75 6d 6d 65 72 6e 20 74 61 75 73 63 68 65 6e } //2 Makro EDV-Nummern tauschen
		$a_00_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 45 44 56 2d 52 61 63 6f 73 22 29 2e 41 75 74 6f 46 69 6c 74 65 72 } //1 ActiveWorkbook.Worksheets("EDV-Racos").AutoFilter
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_23{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 41 53 48 6f 6d 65 39 34 5c 53 41 53 53 63 72 61 74 63 68 5c 62 69 6e 5c 59 6f 75 72 50 61 67 65 2e 70 64 66 } //2 C:\Program Files\SASHome94\SASScratch\bin\YourPage.pdf
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 41 53 48 6f 6d 65 39 34 5c 53 41 53 53 63 72 61 74 63 68 5c 62 69 6e } //2 C:\Program Files\SASHome94\SASScratch\bin
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}
rule _#ASRWin32ApiMacroExclusion_24{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {22 4f 43 47 20 54 72 61 63 6b 65 72 20 56 22 20 26 20 50 61 72 61 6d 73 2e 50 72 6f 70 65 72 74 79 28 22 4f 63 67 54 72 61 63 6b 65 72 56 65 72 73 69 6f 6e 22 29 } //2 "OCG Tracker V" & Params.Property("OcgTrackerVersion")
		$a_00_1 = {61 6c 6c 20 64 61 74 61 20 68 65 6c 64 20 6f 6e 20 74 68 69 73 20 73 79 73 74 65 6d 20 69 73 20 52 45 53 54 52 49 43 54 45 44 } //2 all data held on this system is RESTRICTED
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_25{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 6f 77 63 44 61 79 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub cbowcDay_Change()
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 43 68 6b 53 69 6e 67 6c 65 51 75 65 75 65 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub ChkSingleQueue_Change()
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 6c 62 6c 54 69 74 6c 65 5f 43 6c 69 63 6b 28 29 } //2 Private Sub lblTitle_Click()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_26{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {40 46 6f 6c 64 65 72 28 22 42 69 6e 6f 63 73 2d 41 50 49 2e 44 65 6d 61 6e 64 22 29 } //2 @Folder("Binocs-API.Demand")
		$a_00_1 = {44 69 6d 20 62 69 6e 6f 63 73 41 70 69 20 41 73 20 54 61 62 6c 65 41 70 69 4d 61 6e 61 67 65 72 } //2 Dim binocsApi As TableApiManager
		$a_00_2 = {53 65 74 20 62 69 6e 6f 63 73 41 70 69 20 3d 20 6e 65 77 54 61 62 6c 65 41 70 69 4d 61 6e 61 67 65 } //2 Set binocsApi = newTableApiManage
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_27{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 45 6e 74 72 61 64 61 73 53 61 6c 69 64 61 73 28 29 } //2 Sub EntradasSalidas()
		$a_00_1 = {50 76 74 4e 6f 6d 62 72 65 20 3d 20 22 70 76 74 45 6e 74 72 61 64 61 73 53 61 6c 69 64 61 73 22 } //2 PvtNombre = "pvtEntradasSalidas"
		$a_00_2 = {57 69 6e 64 6f 77 73 28 22 52 65 70 6f 72 74 65 73 5f 44 69 61 72 69 6f 73 2e 78 6c 73 6d 22 29 2e 41 63 74 69 76 61 74 65 } //2 Windows("Reportes_Diarios.xlsm").Activate
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_28{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 53 68 65 65 74 2e 4e 61 6d 65 20 3d 20 22 42 79 67 67 65 70 6c 61 64 73 22 } //2 ActiveSheet.Name = "Byggeplads"
		$a_00_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 4e 61 6d 65 20 3d 20 22 48 75 73 6b 65 6c 69 73 74 65 22 } //2 ActiveSheet.Name = "Huskeliste"
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 65 74 73 28 22 44 65 74 61 69 6c 6b 61 6c 6b 22 29 } //2 Application.Sheets("Detailkalk")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_29{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {4e 6f 6d 62 72 65 4d 61 63 72 6f 20 3d 20 22 4e 6f 6d 62 72 65 20 64 65 20 6c 61 20 6d 61 63 72 6f 20 22 } //2 NombreMacro = "Nombre de la macro "
		$a_00_1 = {6d 73 20 3d 20 6d 73 20 26 20 22 53 69 6e 20 6f 70 65 72 61 63 69 6f 6e 20 65 6e 20 63 65 6d 65 78 20 22 } //2 ms = ms & "Sin operacion en cemex "
		$a_00_2 = {53 75 62 20 4d 6f 64 75 6c 6f 5f 43 6f 6e 73 75 6c 74 61 72 5f 4f 43 28 29 } //2 Sub Modulo_Consultar_OC()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_30{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 74 72 43 6d 64 20 3d 20 70 75 74 74 79 44 69 72 65 63 74 6f 72 79 20 26 20 22 70 6c 69 6e 6b 2e 65 78 65 } //1 strCmd = puttyDirectory & "plink.exe
		$a_00_1 = {53 75 62 20 53 53 48 5f 43 6f 6d 6d 61 6e 64 5f 74 6f 5f 45 78 63 65 6c 5f 50 75 54 54 59 28 29 } //1 Sub SSH_Command_to_Excel_PuTTY()
		$a_00_2 = {44 69 6d 20 70 75 74 74 79 44 69 72 65 63 74 6f 72 79 20 41 73 20 53 74 72 69 6e 67 } //1 Dim puttyDirectory As String
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_31{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {27 4d 73 67 42 6f 78 20 22 53 75 63 63 65 73 73 3a 20 50 44 46 20 63 6f 6e 76 65 72 74 65 64 20 69 6e 74 6f 20 54 65 78 74 } //2 'MsgBox "Success: PDF converted into Text
		$a_01_1 = {27 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 74 75 73 42 61 72 20 3d 20 22 50 44 46 20 4e 61 6d 65 20 63 6f 6e 76 65 72 74 69 6f 6e 20 70 72 6f 63 65 73 73 69 6e 67 2e 2e 2e } //2 'Application.StatusBar = "PDF Name convertion processing...
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_32{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 69 6c 65 4e 61 6d 65 20 3d 20 22 4f 66 66 69 63 69 61 6c 20 53 65 6e 73 69 74 69 76 65 20 51 41 54 52 4f 20 41 73 73 65 73 73 6d 65 6e 74 20 2d 20 22 20 } //2 FileName = "Official Sensitive QATRO Assessment - " 
		$a_00_1 = {53 75 62 20 42 52 50 56 61 6c 69 64 61 74 65 28 29 } //2 Sub BRPValidate()
		$a_00_2 = {53 75 62 20 4f 72 69 67 69 6e 61 6c 5f 52 65 63 6f 72 64 41 73 79 6c 75 6d 28 29 } //2 Sub Original_RecordAsylum()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_33{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {42 61 73 74 69 65 6e 20 4d 65 6e 73 69 6e 6b 20 28 61 75 74 68 6f 72 20 6f 66 20 41 53 41 50 20 55 74 69 6c 69 74 69 65 73 20 61 6e 64 20 77 6f 72 6b 69 6e 67 20 6f 6e 20 69 74 20 73 69 6e 63 65 20 31 39 39 39 29 } //2 Bastien Mensink (author of ASAP Utilities and working on it since 1999)
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //2 https://www.asap-utilities.com
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_34{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 53 74 61 66 66 69 6e 67 53 74 61 74 73 28 42 79 56 61 6c 20 53 69 74 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //2 Function StaffingStats(ByVal SiteName As String)
		$a_00_1 = {63 6e 6e 5f 72 6f 73 74 65 72 2e 45 78 65 63 75 74 65 20 53 51 4c } //2 cnn_roster.Execute SQL
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 57 65 65 6b 6c 79 45 76 65 6e 74 53 74 61 74 73 28 29 } //2 Function WeeklyEventStats()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_35{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 6f 64 79 5f 31 20 3d 20 53 68 65 65 74 73 28 22 4d 61 69 6c 22 29 2e 52 61 6e 67 65 28 22 43 37 22 29 } //2 body_1 = Sheets("Mail").Range("C7")
		$a_01_1 = {62 6f 64 79 20 3d 20 53 68 65 65 74 73 28 22 4d 61 69 6c 22 29 2e 52 61 6e 67 65 28 22 43 38 22 29 } //2 body = Sheets("Mail").Range("C8")
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 63 72 65 65 6e 55 70 64 61 74 69 6e 67 20 3d 20 54 72 75 65 } //2 Application.ScreenUpdating = True
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_36{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 70 6c 61 6e 74 75 6d 6c 2e 63 6f 6d 2f 70 61 74 72 65 6f 6e } //2 http://plantuml.com/patreon
		$a_00_1 = {42 79 20 43 68 69 70 20 50 65 61 72 73 6f 6e 2c 20 63 68 69 70 40 63 70 65 61 72 73 6f 6e 2e 63 6f 6d 2c 20 77 77 77 2e 63 70 65 61 72 73 6f 6e 2e 63 6f 6d } //2 By Chip Pearson, chip@cpearson.com, www.cpearson.com
		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 6c 69 70 73 74 69 63 6b 2e 63 6f 6d } //2 http://www.slipstick.com
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_37{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 76 74 4e 6f 6d 62 72 65 20 3d 20 22 70 76 74 49 6e 76 65 6e 74 61 72 69 6f 46 69 73 69 63 6f 22 } //2 PvtNombre = "pvtInventarioFisico"
		$a_00_1 = {4f 62 6a 2e 41 62 72 69 72 20 28 22 43 69 65 72 72 65 44 69 61 72 69 6f 2e 58 4c 53 22 29 } //2 Obj.Abrir ("CierreDiario.XLS")
		$a_00_2 = {57 69 6e 64 6f 77 73 28 22 49 4e 56 20 44 49 41 52 49 4f 53 20 4a 43 4e 2e 78 6c 73 6d 22 29 2e 41 63 74 69 76 61 74 65 } //2 Windows("INV DIARIOS JCN.xlsm").Activate
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_38{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 63 6c 69 65 6e 74 20 3d 20 6e 65 77 57 65 62 43 6c 69 65 6e 74 28 22 68 74 74 70 73 3a 2f 2f 22 20 26 20 62 69 6e 6f 63 73 45 6e 76 69 72 6f 6e 6d 65 6e 74 20 26 20 22 2e 6d 79 62 69 6e 6f 63 73 2e 63 6f 6d 2f 22 29 } //1 Set client = newWebClient("https://" & binocsEnvironment & ".mybinocs.com/")
		$a_00_1 = {40 46 6f 6c 64 65 72 28 22 42 69 6e 6f 63 73 2d 41 50 49 2e 43 6f 6e 6e 65 63 74 69 6f 6e 22 29 } //1 @Folder("Binocs-API.Connection")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule _#ASRWin32ApiMacroExclusion_39{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 61 6c 63 75 6c 61 74 65 46 75 6c 6c 52 65 62 75 69 6c 64 } //2 Application.CalculateFullRebuild
		$a_00_1 = {53 75 62 20 42 75 74 74 6f 6e 52 61 69 6e 66 61 6c 6c 5f 43 6c 69 63 6b 28 29 } //2 Sub ButtonRainfall_Click()
		$a_00_2 = {41 74 74 72 69 62 75 74 65 20 70 75 74 5f 64 61 74 61 31 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 } //2 Attribute put_data1.VB_ProcData.VB_Invoke_Func
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_40{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 42 46 46 4d 5f 53 45 54 53 45 4c 45 43 54 49 4f 4e 20 3d 20 57 4d 5f 55 53 45 52 20 2b 20 31 30 32 } //2 Private Const BFFM_SETSELECTION = WM_USER + 102
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 42 46 46 4d 5f 49 4e 49 54 49 41 4c 49 5a 45 44 20 3d 20 31 } //2 Private Const BFFM_INITIALIZED = 1
		$a_00_2 = {73 74 72 43 6c 61 73 73 4e 61 6d 65 20 3d 20 22 58 4c 4d 41 49 4e 22 } //2 strClassName = "XLMAIN"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_41{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 61 70 74 75 72 65 5f 69 6e 76 6f 69 63 65 6e 6f 20 3d 20 31 20 54 68 65 6e 20 41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 33 29 } //2 capture_invoiceno = 1 Then ActiveSheet.Cells(lastrow, 3)
		$a_01_1 = {49 66 20 69 6e 76 6f 69 63 65 64 61 74 65 20 3d 20 31 20 54 68 65 6e 20 41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 34 29 20 } //2 If invoicedate = 1 Then ActiveSheet.Cells(lastrow, 4) 
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_42{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {4e 61 6d 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 42 6c 61 73 6d 61 73 63 68 69 6e 65 22 29 2e 52 61 6e 67 65 28 22 41 33 22 29 2e 56 61 6c 75 65 20 26 20 22 44 42 30 22 } //2 Name = Worksheets("Blasmaschine").Range("A3").Value & "DB0"
		$a_00_1 = {4e 61 6d 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 45 74 69 6d 61 22 29 2e 52 61 6e 67 65 28 22 41 33 22 29 2e 56 61 6c 75 65 20 26 20 22 44 42 30 22 } //2 Name = Worksheets("Etima").Range("A3").Value & "DB0"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_43{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 43 6c 65 61 72 5f 43 6f 6e 73 6f 6c 69 64 61 74 65 64 5f 62 79 5f 43 6f 6d 6d 6f 64 69 74 79 28 29 } //2 Sub Clear_Consolidated_by_Commodity()
		$a_00_1 = {53 75 62 20 43 6c 65 61 72 5f 46 6c 6f 75 72 5f 43 6f 6e 74 72 61 63 74 73 5f 62 79 5f 43 4f 50 43 28 29 } //2 Sub Clear_Flour_Contracts_by_COPC()
		$a_00_2 = {53 75 62 20 43 6c 65 61 72 5f 46 6c 6f 75 72 5f 43 6f 6e 74 72 61 63 74 73 5f 62 79 5f 43 4f 4d 4d 28 29 } //2 Sub Clear_Flour_Contracts_by_COMM()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_44{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 70 41 63 63 4d 6f 64 65 20 41 73 20 53 74 72 69 6e 67 } //2 Private pAccMode As String
		$a_00_1 = {70 41 63 63 4d 6f 64 65 20 3d 20 52 65 67 69 73 74 72 79 47 65 74 28 22 47 65 6e 65 72 61 6c 22 2c 20 22 41 63 63 4d 6f 64 65 22 29 } //2 pAccMode = RegistryGet("General", "AccMode")
		$a_00_2 = {4d 73 67 42 6f 78 20 22 4e 6f 74 20 70 6f 73 73 69 62 6c 65 20 77 69 74 68 20 53 68 65 65 74 20 44 72 69 6c 6c 22 } //2 MsgBox "Not possible with Sheet Drill"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_45{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 72 69 62 75 74 65 20 76 62 5f 6e 61 6d 65 20 3d 20 22 6d 6f 64 63 6f 6e 76 65 72 73 69 6f 6e 22 } //2 attribute vb_name = "modconversion"
		$a_00_1 = {70 75 62 6c 69 63 20 63 6f 6e 73 74 20 61 70 70 6e 61 6d 65 20 61 73 20 73 74 72 69 6e 67 20 3d 20 22 65 75 72 6f 20 61 64 64 2d 69 6e 22 } //2 public const appname as string = "euro add-in"
		$a_00_2 = {70 72 69 76 61 74 65 20 73 75 62 20 65 75 72 6f 5f 63 6f 6e 76 65 72 74 5f 65 78 } //2 private sub euro_convert_ex
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_46{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 4e 6f 6e 46 69 6e 61 6e 63 69 61 6c 49 6e 66 6f 54 72 61 6e 73 66 65 72 28 29 } //2 Sub NonFinancialInfoTransfer()
		$a_00_1 = {53 75 62 20 4f 74 68 65 72 45 78 70 65 6e 64 69 74 75 72 65 54 72 61 6e 73 66 65 72 28 29 } //2 Sub OtherExpenditureTransfer()
		$a_00_2 = {44 65 73 6b 74 6f 70 5c 49 6e 76 6f 69 63 69 6e 67 5c 46 6f 73 74 65 72 69 6e 67 20 50 44 46 20 49 6e 76 6f 69 63 65 73 5c 41 62 65 72 64 65 65 6e } //2 Desktop\Invoicing\Fostering PDF Invoices\Aberdeen
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_47{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 57 61 6b 75 4b 65 69 73 65 6e } //2 Private Sub WakuKeisen
		$a_00_1 = {50 75 62 6c 69 63 20 4f 72 61 44 61 74 61 42 61 73 65 20 41 73 20 41 44 4f 44 42 2e 43 6f 6e 6e 65 63 74 69 6f 6e } //2 Public OraDataBase As ADODB.Connection
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 4b 65 69 73 65 6e } //2 Private Sub Keisen
		$a_00_3 = {50 72 69 76 61 74 65 20 53 75 62 20 43 62 62 4b 73 79 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub CbbKsy_Change()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_48{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 63 6c 73 43 42 52 4d 53 68 65 65 74 73 22 } //2 Attribute VB_Name = "clsCBRMSheets"
		$a_00_1 = {47 6c 6f 62 61 6c 20 6d 63 6f 6c 43 42 52 4d 53 68 65 65 74 73 20 41 73 20 63 6f 6c 43 42 52 4d 53 68 65 65 74 73 } //2 Global mcolCBRMSheets As colCBRMSheets
		$a_00_2 = {53 65 74 20 6f 62 6a 43 42 52 4d 53 68 65 65 74 73 20 3d 20 4e 65 77 20 63 6c 73 43 42 52 4d 53 68 65 65 74 73 } //2 Set objCBRMSheets = New clsCBRMSheets
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_49{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 50 72 6f 64 75 63 65 43 61 74 54 65 61 6d 73 28 63 61 74 20 41 73 20 53 74 72 69 6e 67 29 } //2 Function ProduceCatTeams(cat As String)
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 78 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 43 6c 69 63 6b 28 29 } //2 Private Sub cbx_Management_Click()
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 53 68 69 66 74 52 65 71 75 65 73 74 73 5f 49 6e 69 74 69 61 6c 53 65 74 75 70 28 29 } //2 Function ShiftRequests_InitialSetup()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_50{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 73 79 6e 63 53 65 6c 65 63 74 69 6f 6e 28 42 79 56 61 6c 20 54 61 72 67 65 74 20 41 73 20 50 69 76 6f 74 54 61 62 6c 65 29 } //2 Public Sub syncSelection(ByVal Target As PivotTable)
		$a_00_1 = {49 66 20 49 6e 53 74 72 28 70 66 4d 61 69 6e 2e 4e 61 6d 65 2c 20 22 52 65 67 69 6f 6e 22 29 } //2 If InStr(pfMain.Name, "Region")
		$a_00_2 = {49 6e 53 74 72 28 70 66 4d 61 69 6e 2e 4e 61 6d 65 2c 20 22 42 72 61 6e 64 22 29 } //2 InStr(pfMain.Name, "Brand")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_51{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 7a 6f 74 65 72 6f 2e 6f 72 67 } //1 http://zotero.org
		$a_00_1 = {53 75 62 20 5a 6f 74 65 72 6f 43 6f 6d 6d 61 6e 64 28 63 6d 64 20 41 73 20 53 74 72 69 6e 67 2c 20 62 72 69 6e 67 54 6f 46 72 6f 6e 74 20 41 73 20 42 6f 6f 6c 65 61 6e 29 } //1 Sub ZoteroCommand(cmd As String, bringToFront As Boolean)
		$a_00_2 = {50 75 62 6c 69 63 20 53 75 62 20 5a 6f 74 65 72 6f 49 6e 73 65 72 74 42 69 62 6c 69 6f 67 72 61 70 68 79 28 29 } //1 Public Sub ZoteroInsertBibliography()
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_52{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 50 69 76 6f 74 54 61 62 6c 65 73 28 22 70 74 47 72 61 70 68 44 61 74 61 22 29 2e 52 65 66 72 65 73 68 54 61 62 6c 65 } //2 .PivotTables("ptGraphData").RefreshTable
		$a_00_1 = {57 69 74 68 20 2e 50 69 76 6f 74 54 61 62 6c 65 73 28 22 70 74 41 75 64 69 74 54 72 61 69 6c 22 29 } //2 With .PivotTables("ptAuditTrail")
		$a_00_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 55 6e 70 72 6f 74 65 63 74 20 22 4e 6f 72 74 68 67 61 74 65 70 73 22 } //2 ActiveWorkbook.Unprotect "Northgateps"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_53{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 45 6e 75 6d 20 46 72 6d 44 62 6c 50 72 6f 67 72 65 73 73 4c 65 76 65 6c } //2 Public Enum FrmDblProgressLevel
		$a_00_1 = {75 74 69 6c 46 69 6c 65 73 2e 4c 6f 61 64 53 6f 75 72 63 65 46 69 6c 65 20 46 70 61 74 68 2c 20 52 61 77 53 68 74 4e 6d 2c 20 22 5f 72 65 73 22 } //2 utilFiles.LoadSourceFile Fpath, RawShtNm, "_res"
		$a_00_2 = {57 61 73 50 72 6f 74 20 3d 20 44 4d 61 73 74 53 68 74 2e 50 72 6f 74 65 63 74 43 6f 6e 74 65 6e 74 73 } //2 WasProt = DMastSht.ProtectContents
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_54{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {42 5f 56 41 54 5f 57 48 54 5f 44 74 6c 73 } //10 B_VAT_WHT_Dtls
		$a_01_1 = {56 61 74 57 69 74 68 68 6f 6c 64 69 6e 67 45 78 63 65 6c 44 54 4f 2e 74 6f 74 61 6c 50 61 79 61 62 6c 65 41 6d 6f 75 6e 74 } //10 VatWithholdingExcelDTO.totalPayableAmount
		$a_01_2 = {50 49 4e 4e 6f 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 41 5f 42 61 73 69 63 5f 49 6e 66 6f 22 29 2e 52 61 6e 67 65 28 22 53 65 63 41 2e 50 49 4e 22 29 2e 76 61 6c 75 65 } //10 PINNo = Worksheets("A_Basic_Info").Range("SecA.PIN").value
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule _#ASRWin32ApiMacroExclusion_55{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //2 https://www.asap-utilities.com
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 41 53 41 50 6c 49 6c 49 49 6c 6c 6c 6c 6c 6c 6c 49 6c 49 6c 6c 49 6c 49 49 49 49 6c 49 22 } //2 Attribute VB_Name = "ASAPlIlIIlllllllIlIllIlIIIIlI"
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 55 73 65 72 46 6f 72 6d 5f 49 6e 69 74 69 61 6c 69 7a 65 28 29 } //1 Private Sub UserForm_Initialize()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_56{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 50 51 4d 5f 52 65 70 6f 72 74 22 } //2 Attribute VB_Name = "PQM_Report"
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 50 51 4d 5f 41 75 74 6f 6d 61 74 69 6f 6e 22 } //2 Attribute VB_Name = "PQM_Automation"
		$a_00_2 = {53 65 74 20 70 50 51 4d 43 6f 6e 6e 65 63 74 69 6f 6e 20 3d 20 67 5f 6f 62 6a 41 70 70 2e 41 63 74 69 76 65 43 6f 6e 6e 65 63 74 69 6f 6e } //2 Set pPQMConnection = g_objApp.ActiveConnection
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_57{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {76 62 43 72 69 74 69 63 61 6c 2c 20 22 49 54 47 20 44 65 73 69 67 6e 20 7c 20 41 64 64 44 65 73 69 67 6e 50 67 22 } //2 vbCritical, "ITG Design | AddDesignPg"
		$a_00_1 = {53 65 74 20 76 69 73 4d 73 74 72 20 3d 20 76 69 73 4d 73 74 72 73 2e 49 74 65 6d 28 22 43 4b 54 44 65 6d 61 72 6b 22 29 } //2 Set visMstr = visMstrs.Item("CKTDemark")
		$a_00_2 = {76 62 43 72 69 74 69 63 61 6c 2c 20 22 49 54 47 20 44 65 73 69 67 6e 20 7c 20 41 64 64 58 50 52 54 50 67 22 } //2 vbCritical, "ITG Design | AddXPRTPg"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_58{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 42 31 20 3d 20 53 68 65 65 74 73 28 61 72 6b 65 74 29 2e 42 75 74 74 6f 6e 73 28 22 4f 70 72 65 74 50 65 6e 73 69 6f 6e 4b 6f 6e 74 6f 4b 6e 61 70 22 29 } //2 Set B1 = Sheets(arket).Buttons("OpretPensionKontoKnap")
		$a_00_1 = {53 75 62 20 4f 70 72 65 74 50 65 6e 73 69 6f 6e 4b 6f 6e 74 69 4b 6e 61 70 28 29 } //2 Sub OpretPensionKontiKnap()
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 6f 70 72 65 74 5f 70 65 6e 73 69 6f 6e 6b 6f 6e 74 69 28 29 } //2 Private Sub opret_pensionkonti()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_59{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 68 65 6d 44 72 61 77 45 78 63 65 6c 41 64 64 49 6e 32 31 2e 45 78 63 65 6c 41 64 64 49 6e } //1 ChemDrawExcelAddIn21.ExcelAddIn
		$a_00_1 = {63 64 78 6c 64 6f 63 75 6d 65 6e 74 } //1 cdxldocument
		$a_00_2 = {43 53 58 4c 5f 53 68 6f 77 53 74 72 75 63 74 75 72 65 44 72 61 77 69 6e 67 73 } //1 CSXL_ShowStructureDrawings
		$a_00_3 = {43 44 58 4c 41 64 64 49 6e 50 72 6f 67 49 44 } //1 CDXLAddInProgID
		$a_00_4 = {43 53 58 4c 5f 4d 61 6b 65 4e 65 77 43 53 57 6f 72 6b 73 68 65 65 74 } //1 CSXL_MakeNewCSWorksheet
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_60{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {6f 53 6f 75 72 63 65 42 6f 6f 6b 2e 53 61 76 65 41 73 20 73 54 61 72 67 65 74 50 66 61 64 20 26 20 22 54 72 61 66 6f 64 61 74 65 6e 5f 62 65 72 65 69 6e 69 67 74 2e 78 6c 73 78 22 } //2 oSourceBook.SaveAs sTargetPfad & "Trafodaten_bereinigt.xlsx"
		$a_00_1 = {55 73 65 72 66 6f 72 6d 20 65 69 6e 62 6c 65 6e 64 65 6e 20 28 6e 69 63 68 74 20 6d 6f 64 61 6c 29 } //2 Userform einblenden (nicht modal)
		$a_00_2 = {53 75 62 20 44 61 74 65 6e 5f 62 65 72 65 69 6e 69 67 65 6e 28 29 } //2 Sub Daten_bereinigen()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_61{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0f 00 0f 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //10 https://www.asap-utilities.com
		$a_00_1 = {42 61 73 74 69 65 6e 20 4d 65 6e 73 69 6e 6b } //5 Bastien Mensink
		$a_00_2 = {41 74 74 72 69 62 75 74 65 20 42 75 74 74 6f 6e 47 72 6f 75 70 44 79 6e 61 6d 69 63 2e 56 42 5f 56 61 72 48 65 6c 70 49 44 } //5 Attribute ButtonGroupDynamic.VB_VarHelpID
		$a_00_3 = {50 72 69 76 61 74 65 20 54 79 70 65 20 53 48 46 49 4c 45 4f 50 53 54 52 55 43 54 } //5 Private Type SHFILEOPSTRUCT
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5+(#a_00_3  & 1)*5) >=15
 
}
rule _#ASRWin32ApiMacroExclusion_62{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 4d 6f 64 75 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 41 64 64 69 6e 52 65 70 6f 72 74 55 49 22 } //2 Private Const ModuleName As String = "AddinReportUI"
		$a_00_1 = {53 68 65 65 74 73 28 22 41 64 64 2d 69 6e 20 44 65 74 61 69 6c 73 22 29 2e 41 63 74 69 76 61 74 65 } //2 Sheets("Add-in Details").Activate
		$a_00_2 = {53 75 62 20 41 64 6f 70 74 65 64 53 75 70 70 6f 72 74 65 64 47 72 6f 75 70 5f 43 6c 69 63 6b 28 29 } //2 Sub AdoptedSupportedGroup_Click()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_63{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 65 72 4e 61 6d 65 20 3d 20 22 48 4b 53 51 4c 2d 49 4b 41 5c 48 4b 53 51 4c 49 4b 41 22 } //2 ServerName = "HKSQL-IKA\HKSQLIKA"
		$a_00_1 = {64 6e 61 6d 65 20 3d 20 22 49 6b 61 73 61 6e 30 31 22 } //2 dname = "Ikasan01"
		$a_00_2 = {75 4e 61 6d 65 20 3d 20 22 53 59 53 5f 49 4b 41 50 52 44 5f 53 51 4c 22 } //2 uName = "SYS_IKAPRD_SQL"
		$a_00_3 = {64 65 66 5f 73 75 62 6a 65 63 74 20 3d 20 22 46 69 64 65 73 73 61 20 4f 72 64 65 72 20 52 65 70 6f 72 74 20 2d 20 22 } //2 def_subject = "Fidessa Order Report - "
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_64{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {61 74 74 72 69 62 75 74 65 20 76 62 5f 6e 61 6d 65 20 3d 20 22 63 68 72 6f 6e 69 63 6c 65 73 65 78 70 6f 72 74 22 } //2 attribute vb_name = "chroniclesexport"
		$a_00_1 = {70 72 69 76 61 74 65 20 63 6f 6e 73 74 20 6d 6f 64 75 6c 65 20 3d 20 22 65 70 69 63 20 65 78 70 6f 72 74 20 6d 61 63 72 6f 22 } //2 private const module = "epic export macro"
		$a_00_2 = {6f 6e 61 63 74 69 6f 6e 20 3d 20 22 63 68 72 6f 6e 69 63 6c 65 73 65 78 70 6f 72 74 2e 65 78 70 6f 72 74 64 61 74 61 22 } //2 onaction = "chroniclesexport.exportdata"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_65{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 43 6f 6e 74 72 6f 6c 22 29 2e 41 63 74 69 76 61 74 65 } //2 ActiveWorkbook.Worksheets("Control").Activate
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 47 65 74 4d 73 67 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 20 3d 20 22 20 5c 6e 31 34 22 } //2 Attribute GetMsg.VB_ProcData.VB_Invoke_Func = " \n14"
		$a_00_2 = {47 65 74 4d 73 67 20 3d 20 22 4a 72 6e 6c 4c 6f 67 2e 78 6c 73 22 } //2 GetMsg = "JrnlLog.xls"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_66{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 72 65 61 74 65 46 58 43 6f 76 65 72 61 67 65 45 6d 61 69 6c 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 } //2 createFXCoverageEmail.VB_ProcData.VB_Invoke_Func
		$a_00_1 = {63 72 65 61 74 65 46 58 43 6f 76 65 72 61 67 65 45 6d 61 69 6c 43 6f 6d 70 6c 69 61 6e 63 65 } //2 createFXCoverageEmailCompliance
		$a_00_2 = {50 6c 65 61 73 65 20 66 69 6e 64 20 61 74 74 61 63 68 65 64 20 74 68 65 20 46 58 20 43 6f 76 65 72 61 67 65 20 52 65 70 6f 72 74 } //2 Please find attached the FX Coverage Report
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_67{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 46 61 7a 53 70 69 65 67 65 6c 28 29 } //2 Sub FazSpiegel()
		$a_00_1 = {53 75 62 20 46 61 7a 53 70 69 65 67 65 6c 44 69 72 28 73 44 69 72 29 } //2 Sub FazSpiegelDir(sDir)
		$a_00_2 = {63 6f 6e 66 69 67 5c 46 61 7a 73 70 69 65 67 65 6c 2e 69 6e 69 } //2 config\Fazspiegel.ini
		$a_00_3 = {4d 73 67 42 6f 78 20 22 42 69 74 74 65 20 6e 75 74 7a 65 6e 20 73 69 65 20 64 69 65 20 4d 75 73 74 65 72 76 6f 72 6c 61 67 65 20 46 61 7a 73 70 69 65 67 65 6c 2e 78 6c 74 22 } //2 MsgBox "Bitte nutzen sie die Mustervorlage Fazspiegel.xlt"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_68{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 44 65 76 65 6c 6f 70 65 72 20 3d 20 22 6d 65 6c 76 69 6c 63 22 } //2 Public Const Developer = "melvilc"
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 68 6f 72 74 63 75 74 5f 4e 61 6d 65 20 3d 20 22 44 41 43 20 50 6f 72 74 61 6c 2e 6c 6e 6b 22 } //2 Public Const Shortcut_Name = "DAC Portal.lnk"
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 50 6f 72 74 61 6c 5f 46 69 6c 65 4e 61 6d 65 20 3d 20 22 50 6f 72 74 61 6c 2e 78 6c 73 6d 22 } //2 Public Const Portal_FileName = "Portal.xlsm"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_69{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 64 69 74 73 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 64 72 65 61 6d 69 6e 63 6f 64 65 2e 6e 65 74 2f 63 6f 64 65 2f 73 6e 69 70 70 65 74 35 34 30 2e 68 74 6d } //2 Credits: http://www.dreamincode.net/code/snippet540.htm
		$a_00_1 = {47 42 52 20 4e 4f 54 45 3a 20 54 68 69 73 20 77 6f 72 6b 73 2c 20 62 75 74 20 77 65 20 68 61 76 65 20 6e 6f 20 61 63 63 65 73 73 20 74 6f 20 73 74 64 69 6e 2c 20 73 74 64 6f 75 74 20 6f 72 20 73 74 64 65 72 72 2e 2e 2e } //2 GBR NOTE: This works, but we have no access to stdin, stdout or stderr...
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_70{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 52 65 66 72 65 73 68 5f 41 43 54 5f 46 43 53 54 5f 4c 4d 52 28 29 } //2 Sub Refresh_ACT_FCST_LMR()
		$a_00_1 = {61 63 63 41 70 70 2e 64 6f 63 6d 64 2e 6f 70 65 6e 71 75 65 72 79 20 28 22 4c 4d 52 20 52 65 63 68 6e 75 6e 67 73 64 61 74 65 6e 20 55 70 64 61 74 65 20 54 61 62 65 6c 6c 65 22 29 } //2 accApp.docmd.openquery ("LMR Rechnungsdaten Update Tabelle")
		$a_00_2 = {75 4f 46 4e 2e 73 44 6c 67 54 69 74 6c 65 20 3d 20 22 44 61 74 65 69 20 73 70 65 69 63 68 65 72 6e 20 75 6e 74 65 72 22 } //2 uOFN.sDlgTitle = "Datei speichern unter"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_71{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 6d 5f 50 41 53 53 57 4f 52 44 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 50 75 6c 73 30 30 33 31 31 34 22 } //2 Private Const m_PASSWORD As String = "Puls003114"
		$a_00_1 = {52 69 62 62 6f 6e 43 6f 6e 74 72 6f 6c 52 65 66 72 65 73 68 20 22 62 74 6e 52 65 73 65 74 4d 61 72 6b 73 22 } //2 RibbonControlRefresh "btnResetMarks"
		$a_00_2 = {53 65 74 20 6d 5f 6f 52 6f 6f 74 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 4c 44 41 50 3a 2f 2f 52 6f 6f 74 44 53 45 22 29 } //2 Set m_oRoot = GetObject("LDAP://RootDSE")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_72{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 41 70 70 4e 61 6d 65 20 3d 20 22 47 54 20 50 44 46 4d 65 6c 64 20 54 6f 6f 6c 6b 69 74 22 } //1 Public Const AppName = "GT PDFMeld Toolkit"
		$a_00_1 = {43 6f 6e 73 74 20 50 44 46 42 61 74 63 68 46 69 6c 65 20 3d 20 22 52 75 6e 50 44 46 4d 65 6c 64 2e 62 61 74 22 } //1 Const PDFBatchFile = "RunPDFMeld.bat"
		$a_00_2 = {41 75 74 68 6f 72 20 3a 20 45 6a 61 7a 20 41 68 6d 65 64 20 2d 20 65 6a 61 7a 2e 61 68 6d 65 64 2e 31 39 38 39 40 67 6d 61 69 6c 2e 63 6f 6d } //1 Author : Ejaz Ahmed - ejaz.ahmed.1989@gmail.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_73{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 62 6f 6f 6b 20 3d 20 77 62 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 41 64 64 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 73 70 69 6e 6e 65 72 2e 78 6c 73 6d 22 29 } //2 Set book = wb.Workbooks.Add(ThisWorkbook.Path & "\spinner.xlsm")
		$a_00_1 = {53 75 62 20 44 6f 43 61 6c 63 54 69 6d 65 72 28 6a 4d 65 74 68 6f 64 20 41 73 20 4c 6f 6e 67 29 } //1 Sub DoCalcTimer(jMethod As Long)
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 4d 69 63 72 6f 54 69 6d 65 72 28 29 20 41 73 20 44 6f 75 62 6c 65 } //1 Function MicroTimer() As Double
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_74{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {42 61 74 46 69 6c 65 20 3d 20 22 63 3a 5c 74 65 6d 70 5c 73 6f 66 74 6c 69 6e 6b 70 72 6f 6d 6f 74 65 74 6f 6d 61 73 74 65 72 2e 63 6d 64 22 } //2 BatFile = "c:\temp\softlinkpromotetomaster.cmd"
		$a_00_1 = {42 61 74 46 69 6c 65 20 3d 20 22 63 3a 5c 74 65 6d 70 5c 73 6f 66 74 6c 69 6e 6b 62 72 61 6e 63 68 73 65 74 75 70 2e 63 6d 64 22 } //2 BatFile = "c:\temp\softlinkbranchsetup.cmd"
		$a_00_2 = {6d 66 69 6c 65 2c 20 22 70 6c 69 6e 6b 20 2d 70 77 20 62 75 69 6c 64 20 62 75 69 6c 64 40 74 68 65 74 61 20 22 } //2 mfile, "plink -pw build build@theta "
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_75{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 66 64 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 46 69 6c 65 44 69 61 6c 6f 67 28 6d 73 6f 46 69 6c 65 44 69 61 6c 6f 67 46 6f 6c 64 65 72 50 69 63 6b 65 72 29 } //1 Set fd = Application.FileDialog(msoFileDialogFolderPicker)
		$a_00_1 = {41 75 74 68 6f 72 3a 20 44 61 76 69 64 20 4d 6f 73 69 65 72 2c 20 4e 65 69 6c 20 4a 6f 68 6e 73 6f 6e } //1 Author: David Mosier, Neil Johnson
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 44 41 47 73 46 69 6c 65 20 3d 20 22 44 41 47 49 6e 66 6f 2e 63 73 76 22 } //1 Public Const DAGsFile = "DAGInfo.csv"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_76{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 53 75 62 46 6f 6c 64 65 72 32 20 3d 20 53 75 62 46 6f 6c 64 65 72 2e 46 6f 6c 64 65 72 73 28 22 4e 49 4e 4f 20 76 32 20 49 50 54 20 54 69 65 72 20 32 20 65 6d 61 69 6c 73 22 29 } //2 Set SubFolder2 = SubFolder.Folders("NINO v2 IPT Tier 2 emails")
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 4d 6f 76 65 45 6d 61 69 6c 73 54 6f 49 50 54 41 72 63 68 69 76 65 28 29 } //2 Public Sub MoveEmailsToIPTArchive()
		$a_00_2 = {44 69 6d 20 49 6e 62 6f 78 20 41 73 20 4f 75 74 6c 6f 6f 6b 2e 4d 41 50 49 46 6f 6c 64 65 72 } //2 Dim Inbox As Outlook.MAPIFolder
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_77{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 72 65 63 75 70 65 72 65 5f 74 61 62 6c 65 5f 75 74 69 6c 69 73 61 74 65 75 72 73 28 29 20 41 73 20 56 61 72 69 61 6e 74 } //2 Function recupere_table_utilisateurs() As Variant
		$a_00_1 = {53 71 6c 20 3d 20 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 30 35 5f 55 50 53 5f 43 72 65 77 20 22 } //2 Sql = "SELECT * FROM 05_UPS_Crew "
		$a_00_2 = {53 75 62 20 52 65 74 72 6f 75 76 65 5f 61 6e 61 6c 79 73 65 73 5f 6e 6f 6e 5f 72 65 6c 65 61 73 65 65 73 5f 73 61 6e 73 5f 65 6d 61 69 6c 28 29 } //2 Sub Retrouve_analyses_non_releasees_sans_email()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_78{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 74 68 69 73 57 6f 72 6b 73 68 65 65 74 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 43 50 20 43 6c 69 65 6e 74 22 29 } //2 Set thisWorksheet = ActiveWorkbook.Worksheets("CP Client")
		$a_00_1 = {53 75 62 20 74 72 61 6e 73 66 65 72 5f 62 69 6e 61 72 69 65 73 5f 74 6f 5f 4d 65 74 61 4d 6f 6e 28 29 } //2 Sub transfer_binaries_to_MetaMon()
		$a_00_2 = {53 75 62 20 74 72 61 6e 73 66 65 72 5f 62 69 6e 61 72 69 65 73 5f 74 6f 5f 4c 33 5f 74 65 73 74 5f 74 65 61 6d 28 29 } //2 Sub transfer_binaries_to_L3_test_team()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_79{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 6c 5f 63 6f 6e 74 72 6f 6c 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 2e 46 69 6e 64 43 6f 6e 74 72 6f 6c 28 54 61 67 3a 3d 22 44 46 57 46 69 6c 74 65 72 22 29 } //1 Set l_control = Application.CommandBars.FindControl(Tag:="DFWFilter")
		$a_00_1 = {53 65 74 20 6c 53 68 61 70 65 20 3d 20 6c 53 68 65 65 74 2e 53 68 61 70 65 73 28 22 49 6e 66 6f 41 22 29 } //1 Set lShape = lSheet.Shapes("InfoA")
		$a_00_2 = {49 6e 53 74 72 28 31 2c 20 6c 53 68 61 70 65 2e 4e 61 6d 65 2c 20 22 42 45 78 22 29 } //1 InStr(1, lShape.Name, "BEx")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_80{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 64 20 62 79 20 2d 20 42 72 6f 63 68 65 74 20 6c 74 64 } //1 Created by - Brochet ltd
		$a_00_1 = {77 77 77 2e 62 72 6f 63 68 65 74 2e 63 6f 2e 75 6b } //1 www.brochet.co.uk
		$a_00_2 = {41 75 74 68 6f 72 3a 44 75 6e 63 61 6e 20 4d 69 6c 6e 65 73 20 2d 20 42 72 6f 63 68 65 74 } //1 Author:Duncan Milnes - Brochet
		$a_00_3 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 43 4f 4d 50 41 4e 59 5f 4e 41 4d 45 5f 53 48 4f 52 54 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 46 72 61 7a 65 72 2d 4e 61 73 68 22 } //1 Public Const COMPANY_NAME_SHORT As String = "Frazer-Nash"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_81{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 50 4c 41 4e 34 5c 45 58 43 45 4c 5c 58 4c 53 31 33 38 42 2e 58 4c 53 20 32 30 30 34 2d 30 32 2d 30 35 } //2 EPLAN4\EXCEL\XLS138B.XLS 2004-02-05
		$a_00_1 = {50 75 62 6c 69 63 20 41 6e 7a 65 69 67 65 5f 50 72 6f 7a 65 6e 74 20 41 73 20 53 74 72 69 6e 67 } //2 Public Anzeige_Prozent As String
		$a_00_2 = {50 75 62 6c 69 63 20 41 72 74 69 6b 65 6c 6b 65 6e 6e 75 6e 67 20 41 73 20 4c 6f 6e 67 } //2 Public Artikelkennung As Long
		$a_00_3 = {50 75 62 6c 69 63 20 4d 65 72 6b 65 72 5f 41 72 74 69 6b 65 6c 74 79 70 20 41 73 20 4c 6f 6e 67 } //2 Public Merker_Artikeltyp As Long
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_82{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 68 6f 72 74 63 75 74 5f 4e 61 6d 65 20 3d 20 22 53 53 52 43 20 50 6f 72 74 61 6c 2e 6c 6e 6b 22 } //2 Public Const Shortcut_Name = "SSRC Portal.lnk"
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 49 63 6f 6e 5f 44 65 73 63 72 69 70 74 69 6f 6e 20 3d 20 22 53 53 52 43 20 50 6f 72 74 61 6c 22 } //2 Public Const Icon_Description = "SSRC Portal"
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 50 6f 72 74 61 6c 5f 46 69 6c 65 4e 61 6d 65 20 3d 20 22 50 6f 72 74 61 6c 2e 78 6c 73 6d 22 } //2 Public Const Portal_FileName = "Portal.xlsm"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_83{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 36 20 2d 20 49 6e 66 61 6e 74 20 46 65 65 64 69 6e 67 22 29 } //2 ActiveWorkbook.Worksheets("6 - Infant Feeding")
		$a_00_1 = {53 65 72 76 69 63 65 43 6f 6d 62 6f 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 22 54 6f 6e 67 75 65 2d 74 69 65 20 73 75 70 70 6f 72 74 22 } //2 ServiceComboBox1.AddItem "Tongue-tie support"
		$a_00_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 4f 75 74 70 75 74 73 5f 53 46 4c 49 46 4d 48 22 29 } //2 ActiveWorkbook.Worksheets("Outputs_SFLIFMH")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_84{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 58 4c 50 79 44 4c 4c 4e 44 69 6d 73 20 4c 69 62 20 22 78 6c 77 69 6e 67 73 36 34 2e 64 6c 6c 22 } //2 Declare PtrSafe Function XLPyDLLNDims Lib "xlwings64.dll"
		$a_00_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 58 4c 50 79 44 4c 4c 4e 44 69 6d 73 20 4c 69 62 20 22 78 6c 77 69 6e 67 73 33 32 2e 64 6c 6c 22 } //2 Private Declare PtrSafe Function XLPyDLLNDims Lib "xlwings32.dll"
		$a_00_2 = {78 6c 77 69 6e 67 73 5f 6c 6f 67 2e 74 78 74 } //2 xlwings_log.txt
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_85{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 65 69 6e 67 61 62 65 62 6c 61 74 74 46 6f 72 6d 65 6c 6e 28 29 } //1 Sub eingabeblattFormeln()
		$a_00_1 = {53 65 74 20 77 73 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 45 69 6e 67 61 62 65 22 29 } //1 Set ws = ThisWorkbook.Worksheets("Eingabe")
		$a_00_2 = {73 61 66 65 70 61 74 68 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 4d 46 54 2d 4e 2d 50 61 74 65 6e 2d 42 6c 61 74 74 2e 78 6c 73 78 22 } //1 safepath = Application.ActiveWorkbook.Path & "\MFT-N-Paten-Blatt.xlsx"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_86{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 47 65 6e 55 75 69 64 28 73 55 75 69 64 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //1 Private Function GenUuid(sUuid As String) As Boolean
		$a_00_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 69 73 53 41 50 44 6f 63 28 6b 65 79 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //1 Public Function isSAPDoc(key As String) As Boolean
		$a_00_2 = {43 61 73 65 20 49 73 20 3d 20 22 53 41 50 47 72 6f 75 70 22 20 20 27 20 53 74 79 6c 65 73 20 67 72 6f 75 70 } //1 Case Is = "SAPGroup"  ' Styles group
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_87{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 73 65 6c 65 63 74 20 61 20 63 65 6c 6c 20 74 68 61 74 20 69 73 20 6e 6f 74 20 62 6c 61 6e 6b 20 6f 72 20 63 6f 6e 74 61 69 6e 73 20 61 20 76 61 6c 69 64 61 74 69 6f 6e 20 6c 69 73 74 } //2 Please select a cell that is not blank or contains a validation list
		$a_01_1 = {4c 69 73 74 73 20 74 68 61 74 20 63 6f 6e 74 61 69 6e 20 6d 6f 72 65 20 74 68 61 6e 20 32 2c 30 30 30 20 69 74 65 6d 73 20 6d 61 79 20 74 61 6b 65 20 61 64 64 69 74 69 6f 6e 61 6c 20 74 69 6d 65 20 74 6f 20 73 6f 72 74 2e } //2 Lists that contain more than 2,000 items may take additional time to sort.
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_88{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 44 6f 43 61 6c 63 54 69 6d 65 72 28 6a 4d 65 74 68 6f 64 20 41 73 20 4c 6f 6e 67 29 } //2 Sub DoCalcTimer(jMethod As Long)
		$a_00_1 = {53 65 74 20 62 6f 6f 6b 20 3d 20 77 62 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 41 64 64 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 73 70 69 6e 6e 65 72 2e 78 6c 73 6d 22 29 } //2 Set book = wb.Workbooks.Add(ThisWorkbook.Path & "\spinner.xlsm")
		$a_00_2 = {73 43 61 6c 63 54 79 70 65 20 3d 20 22 52 65 63 61 6c 63 75 6c 61 74 65 20 6f 70 65 6e 20 77 6f 72 6b 62 6f 6f 6b 73 3a 20 22 } //2 sCalcType = "Recalculate open workbooks: "
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_89{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 41 53 41 50 20 55 74 69 6c 69 74 69 65 73 2e 78 6c 61 6d 22 29 2e 50 61 74 68 } //2 Workbooks("ASAP Utilities.xlam").Path
		$a_00_1 = {41 53 41 50 52 69 62 62 6f 6e 5f 49 6e 69 74 69 61 6c 69 7a 65 28 72 69 62 62 6f 6e 20 41 73 20 49 52 69 62 62 6f 6e 55 49 29 } //2 ASAPRibbon_Initialize(ribbon As IRibbonUI)
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 41 53 41 50 52 75 6e 50 72 6f 63 5f 78 36 34 22 } //2 Application.Run "ASAPRunProc_x64"
		$a_00_3 = {77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //2 www.asap-utilities.com
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_90{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 6c 73 50 72 6f 70 65 72 74 69 65 73 2e 72 65 6d 6f 76 65 50 72 6f 70 65 72 74 79 20 22 49 43 58 5f 53 45 53 53 49 4f 4e 5f 49 44 22 } //2 clsProperties.removeProperty "ICX_SESSION_ID"
		$a_00_1 = {45 52 56 4c 45 54 5f 50 41 54 48 20 3d 20 22 68 74 74 70 3a 2f 2f 65 62 73 70 72 64 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 61 6d 63 2e 63 6f 72 70 3a 38 30 2f 4f 41 5f 48 54 4d 4c 2f 22 } //2 ERVLET_PATH = "http://ebsprd.homeoffice.amc.corp:80/OA_HTML/"
		$a_00_2 = {50 75 62 6c 69 63 20 53 75 62 20 42 6e 65 4f 6e 43 72 65 61 74 65 50 72 6f 63 65 64 75 72 65 28 29 } //2 Public Sub BneOnCreateProcedure()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_91{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 50 41 54 48 44 45 53 54 20 3d 20 22 48 3a 5c 63 61 70 61 63 69 74 79 5c 54 6f 6f 6c 5c 44 61 74 61 } //2 Private Const PATHDEST = "H:\capacity\Tool\Data
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 50 41 54 48 44 45 53 54 44 41 54 41 53 20 3d 20 22 48 3a 5c 63 61 70 61 63 69 74 79 5c 54 6f 6f 6c 5c 50 6f 63 5f 44 61 74 61 73 } //2 Private Const PATHDESTDATAS = "H:\capacity\Tool\Poc_Datas
		$a_00_2 = {73 74 72 53 71 6c 20 3d 20 22 55 70 64 61 74 65 43 61 70 61 70 6c 61 6e 6e 69 6e 67 56 4d 53 69 7a 65 22 } //2 strSql = "UpdateCapaplanningVMSize"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_92{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 70 6f 70 75 6c 61 74 65 5f 47 6c 6f 62 61 6c 73 } //2 Call populate_Globals
		$a_00_1 = {49 66 20 74 4d 69 6c 65 73 74 6f 6e 65 73 28 74 61 73 6b 43 6f 75 6e 74 29 2e 70 72 6f 6a 55 49 44 20 3d 20 22 52 65 74 61 69 6c 20 52 65 63 6f 72 64 73 20 4d 61 6e 61 67 65 6d 65 6e 74 20 50 72 6f 67 72 61 6d 6d 65 2d 31 38 34 22 20 54 68 65 6e 20 53 74 6f 70 } //2 If tMilestones(taskCount).projUID = "Retail Records Management Programme-184" Then Stop
		$a_00_2 = {53 75 62 20 6c 69 6e 6b 5f 4d 69 6c 65 73 74 6f 6e 65 73 28 70 72 65 49 44 2c 20 73 75 63 49 44 29 } //2 Sub link_Milestones(preID, sucID)
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_93{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 50 4f 5f 43 61 6e 63 65 6c 6c 61 74 69 6f 6e 5f 50 72 6f 63 65 73 73 28 29 } //2 Sub PO_Cancellation_Process()
		$a_00_1 = {53 68 65 65 74 73 28 22 50 4f 20 44 65 74 61 69 6c 73 22 29 } //2 Sheets("PO Details")
		$a_00_2 = {50 4f 5f 41 64 73 20 3d 20 53 41 50 53 63 72 69 70 74 2e 46 69 6e 64 5f 41 64 64 73 28 22 53 61 6c 65 73 20 6f 72 64 65 72 20 6e 6f 22 29 3a 20 4d 61 74 5f 41 64 73 20 3d 20 53 41 50 53 63 72 69 70 74 2e 46 69 6e 64 5f 41 64 64 73 28 22 50 61 72 74 20 4e 75 6d 62 65 72 22 29 } //2 PO_Ads = SAPScript.Find_Adds("Sales order no"): Mat_Ads = SAPScript.Find_Adds("Part Number")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_94{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 74 75 73 42 61 72 20 3d 20 22 50 72 65 70 61 72 69 6e 67 20 66 6f 72 20 53 41 4d 50 20 61 6e 61 6c 79 73 69 73 22 } //2 Application.StatusBar = "Preparing for SAMP analysis"
		$a_00_1 = {49 66 20 55 43 61 73 65 28 56 42 43 6f 6e 73 74 61 6e 74 73 2e 52 61 6e 67 65 28 22 53 41 4d 50 5f 52 55 4e 5f 44 41 54 45 22 29 2e 56 61 6c 75 65 32 29 20 3c 3e 20 22 22 20 54 68 65 6e 20 45 78 69 74 20 53 75 62 } //2 If UCase(VBConstants.Range("SAMP_RUN_DATE").Value2) <> "" Then Exit Sub
		$a_00_2 = {43 61 6c 6c 20 46 69 78 5f 52 69 62 62 6f 6e 5f 4d 50 } //2 Call Fix_Ribbon_MP
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_95{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 47 65 6e 65 72 61 74 65 53 46 52 51 75 65 72 79 28 29 } //1 Sub GenerateSFRQuery()
		$a_00_1 = {4d 73 67 42 6f 78 20 22 53 46 52 20 71 75 65 72 79 20 63 6f 70 69 65 64 20 74 6f 20 63 6c 69 70 62 6f 61 72 64 22 } //1 MsgBox "SFR query copied to clipboard"
		$a_00_2 = {73 66 72 5f 6c 69 6e 6b 20 3d 20 22 68 74 74 70 3a 2f 2f 73 66 72 2f 70 72 6f 64 41 73 70 2f 73 63 72 69 70 74 73 2f 4d 53 47 2f 73 66 72 2e 61 73 70 3f 73 66 72 3d 22 } //1 sfr_link = "http://sfr/prodAsp/scripts/MSG/sfr.asp?sfr="
		$a_00_3 = {53 75 62 20 43 72 65 61 74 65 53 46 52 44 65 73 63 4c 69 73 74 28 29 } //1 Sub CreateSFRDescList()
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_96{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 43 50 50 6c 75 73 47 49 2e 43 72 65 61 74 65 45 64 69 74 5f 47 49 43 61 73 65 22 29 } //2 Call Application.Run("CPPlusGI.CreateEdit_GICase")
		$a_00_1 = {4d 73 67 42 6f 78 20 4e 6f 77 20 26 20 76 62 43 72 4c 66 20 26 20 22 4d 69 74 6f 67 65 6e 2e 45 64 69 74 43 61 73 65 28 29 22 } //2 MsgBox Now & vbCrLf & "Mitogen.EditCase()"
		$a_00_2 = {45 6e 64 20 49 66 20 27 47 65 74 56 61 72 69 61 62 6c 65 28 22 45 6e 61 62 6c 65 47 65 6e 65 49 6e 73 69 67 68 74 22 2c 20 64 44 6f 63 2e 4e 61 6d 65 29 } //2 End If 'GetVariable("EnableGeneInsight", dDoc.Name)
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_97{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 53 68 61 72 65 64 20 43 6f 6e 74 72 6f 6c 20 52 6f 6f 6d 20 53 4f 43 43 55 49 20 69 73 20 61 6c 72 65 61 64 79 20 6f 70 65 6e } //2 The Shared Control Room SOCCUI is already open
		$a_01_1 = {54 68 69 73 20 77 69 6c 6c 20 72 65 73 75 6c 74 20 69 6e 20 63 68 61 6e 67 65 73 20 73 61 76 65 64 20 69 6e 20 74 68 65 20 53 4f 43 43 55 49 } //2 This will result in changes saved in the SOCCUI
		$a_01_2 = {43 6c 6f 73 69 6e 67 20 74 68 69 73 20 63 6f 70 79 20 6f 66 20 74 68 65 20 53 68 61 72 65 64 20 43 6f 6e 74 72 6f 6c 20 52 6f 6f 6d 20 53 4f 43 43 55 49 } //2 Closing this copy of the Shared Control Room SOCCUI
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_98{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 61 64 64 5f 4d 69 6c 65 73 74 6f 6e 65 73 28 73 68 6f 77 53 6c 69 70 2c 20 78 6c 4e 61 6d 65 29 } //1 Sub add_Milestones(showSlip, xlName)
		$a_00_1 = {43 6f 6d 6d 65 6e 63 69 6e 67 20 52 65 70 6f 72 74 69 6e 67 } //1 Commencing Reporting
		$a_00_2 = {52 65 74 61 69 6c 20 52 65 63 6f 72 64 73 20 4d 61 6e 61 67 65 6d 65 6e 74 20 50 72 6f 67 72 61 6d 6d 65 2d 31 38 34 } //1 Retail Records Management Programme-184
		$a_00_3 = {74 4d 69 6c 65 73 74 6f 6e 65 73 28 74 61 73 6b 43 6f 75 6e 74 29 } //1 tMilestones(taskCount)
		$a_00_4 = {22 4d 69 6c 65 73 74 6f 6e 65 20 53 77 69 6d 6c 61 6e 65 22 } //1 "Milestone Swimlane"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_99{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6d 70 72 65 73 73 69 6f 6e 20 64 75 20 66 6f 72 6d 75 6c 61 69 72 65 20 64 27 61 75 64 69 74 20 35 53 20 70 6f 75 72 20 6c 65 73 20 73 74 6f 63 6b 73 } //10 Impression du formulaire d'audit 5S pour les stocks
		$a_01_1 = {6c 65 74 74 72 65 73 20 70 6f 75 72 20 61 66 66 69 63 68 61 67 65 20 73 75 72 20 6c 65 20 74 61 62 6c 65 61 75 20 64 65 20 73 65 63 74 65 75 72 } //10 lettres pour affichage sur le tableau de secteur
		$a_01_2 = {27 20 43 68 6f 69 78 20 61 6c e9 61 74 6f 69 72 65 20 64 65 20 6c 61 20 71 75 65 73 74 69 6f 6e 20 65 6e 76 69 72 6f 6e 6e 65 6d 65 6e 74 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=30
 
}
rule _#ASRWin32ApiMacroExclusion_100{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 44 69 65 73 65 41 72 62 65 69 74 73 6d 61 70 70 65 22 } //2 Attribute VB_Name = "DieseArbeitsmappe"
		$a_00_1 = {53 65 74 20 6f 42 61 72 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 2e 41 64 64 28 22 4b 52 4f 4e 45 53 22 29 } //2 Set oBar = Application.CommandBars.Add("KRONES")
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 4b 52 4f 4e 45 53 22 29 2e 43 6f 6e 74 72 6f 6c 73 28 22 45 78 65 63 75 74 65 22 29 2e 44 65 6c 65 74 65 } //2 Application.CommandBars("KRONES").Controls("Execute").Delete
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_101{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 6c 65 61 73 65 20 75 70 67 72 61 64 65 20 54 68 6f 6d 73 6f 6e 20 52 65 75 74 65 72 73 20 45 69 6b 6f 6e 20 45 78 63 65 6c } //1 Please upgrade Thomson Reuters Eikon Excel
		$a_00_1 = {50 6c 65 61 73 65 20 73 69 67 6e 20 69 6e 20 74 6f 20 54 68 6f 6d 73 6f 6e 20 52 65 75 74 65 72 73 20 45 69 6b 6f 6e 20 45 78 63 65 6c } //1 Please sign in to Thomson Reuters Eikon Excel
		$a_00_2 = {43 6f 6d 6d 61 6e 64 54 65 78 74 20 3d 20 41 72 72 61 79 28 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 5b 68 74 74 70 3a 2f 2f 66 6c 6f 77 20 67 61 73 73 63 6f 20 6e 6f 2f 5d 22 29 } //1 CommandText = Array("SELECT * FROM [http://flow gassco no/]")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_102{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 4c 4d 54 5f 47 65 74 45 71 75 69 76 61 6c 65 6e 74 52 61 74 69 6e 67 } //2 Public Function LMT_GetEquivalentRating
		$a_00_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 4c 4d 54 5f 47 65 74 50 61 72 74 79 43 72 65 64 69 74 52 61 74 69 6e 67 } //2 Public Function LMT_GetPartyCreditRating
		$a_00_2 = {53 65 74 20 64 62 73 44 61 74 61 62 61 73 65 5f 35 41 4d 20 3d 20 4f 70 65 6e 44 61 74 61 62 61 73 65 28 22 46 69 6e 64 75 72 5f 35 61 6d 22 2c 20 46 61 6c 73 65 2c 20 54 72 75 65 2c 20 22 4f 44 42 43 3b 22 29 } //2 Set dbsDatabase_5AM = OpenDatabase("Findur_5am", False, True, "ODBC;")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_103{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 66 72 61 6d 65 43 61 70 74 69 6f 6e 24 20 3d 20 22 49 6d 70 61 63 74 20 6f 6e 20 4e 61 74 69 6f 6e 61 6c 20 53 65 63 75 72 69 74 79 20 2f 20 49 6e 66 72 61 73 74 72 75 63 74 75 72 65 22 } //2 Private Const frameCaption$ = "Impact on National Security / Infrastructure"
		$a_00_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 46 69 78 55 70 5f 63 72 69 6d 69 6e 61 6c 69 74 79 44 61 74 61 28 29 } //2 Public Function FixUp_criminalityData()
		$a_00_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 46 69 78 55 70 5f 6d 61 6e 61 67 65 6d 65 6e 74 44 61 74 61 28 29 } //2 Public Function FixUp_managementData()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_104{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 52 45 6e 64 20 3d 20 53 68 65 65 74 73 28 22 4e 47 4c 20 53 44 46 49 20 2d 20 49 4b 4b 45 20 52 } //1 Set REnd = Sheets("NGL SDFI - IKKE R
		$a_00_1 = {52 22 29 2e 52 61 6e 67 65 28 22 41 34 30 30 22 29 2e 45 6e 64 28 78 6c 55 70 29 2e 4f 66 66 73 65 74 28 30 2c 20 33 29 } //1 R").Range("A400").End(xlUp).Offset(0, 3)
		$a_00_2 = {53 65 74 20 52 53 74 61 72 74 20 3d 20 52 61 6e 67 65 28 22 41 32 22 29 } //1 Set RStart = Range("A2")
		$a_00_3 = {49 66 20 57 6f 72 6b 73 68 65 65 74 46 75 6e 63 74 69 6f 6e 2e 43 6f 75 6e 74 42 6c 61 6e 6b 28 2e 52 6f 77 73 28 69 29 29 20 3d 20 34 20 54 68 65 6e } //1 If WorksheetFunction.CountBlank(.Rows(i)) = 4 Then
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_105{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {57 6f 72 64 49 6e 74 65 67 72 61 74 69 6f 6e 2e 46 69 6c 6c 4c 69 73 74 57 6f 72 64 74 61 62 6c 65 20 63 62 50 72 6f 64 75 63 74 73 2c 20 22 65 3a 5c 57 6f 72 64 54 65 6d 70 6c 61 74 65 5c 44 61 74 61 5c 50 72 6f 64 75 63 74 73 2e 64 6f 63 6d 22 } //1 WordIntegration.FillListWordtable cbProducts, "e:\WordTemplate\Data\Products.docm"
		$a_00_1 = {63 62 50 72 6f 64 75 63 74 73 2c 20 22 68 74 74 70 3a 2f 2f 63 6f 6d 70 61 73 73 32 73 69 74 65 73 2e 70 65 72 73 63 6f 72 70 2e 63 6f 6d 2f 73 69 74 65 73 2f 31 31 36 33 2f 44 61 74 61 2f 50 72 6f 64 75 63 74 73 2e 64 6f 63 6d 22 } //1 cbProducts, "http://compass2sites.perscorp.com/sites/1163/Data/Products.docm"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule _#ASRWin32ApiMacroExclusion_106{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 55 6e 70 72 6f 74 65 63 74 20 50 61 73 73 77 6f 72 64 3a 3d 22 48 52 53 53 53 41 22 } //1 ActiveWorkbook.Unprotect Password:="HRSSSA"
		$a_00_1 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 43 6f 70 79 41 73 20 73 74 72 50 61 74 68 20 26 20 22 5c 48 52 2d 45 6d 70 6c 6f 79 6d 65 6e 74 2d 46 6f 72 6d 5f 4e 65 77 2e 78 6c 73 62 22 } //1 ActiveWorkbook.SaveCopyAs strPath & "\HR-Employment-Form_New.xlsb"
		$a_00_2 = {77 73 50 61 72 61 6d 65 74 65 72 73 2e 52 61 6e 67 65 28 22 46 69 6c 65 4e 61 6d 65 32 22 29 20 3d 20 22 48 52 46 52 4d 47 4e 41 2e 63 73 76 22 } //1 wsParameters.Range("FileName2") = "HRFRMGNA.csv"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_107{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 54 69 74 75 6c 6f 20 3d 20 22 53 65 6c 65 63 69 6f 6e 65 20 75 6d 20 61 72 71 75 69 76 6f 20 44 4f 43 22 } //1 sTitulo = "Selecione um arquivo DOC"
		$a_00_1 = {4d 6f 64 65 6c 6f 20 70 61 72 61 20 55 6e 69 72 20 6f 73 20 54 52 56 73 2e 64 6f 63 6d } //1 Modelo para Unir os TRVs.docm
		$a_00_2 = {53 65 74 20 44 4f 43 20 3d 20 57 6f 72 64 2e 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 28 6c 50 61 73 74 61 20 26 20 22 5c 55 6e 69 54 52 56 73 2e 64 6f 63 6d 22 29 } //1 Set DOC = Word.Documents.Open(lPasta & "\UniTRVs.docm")
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 64 69 72 65 74 6f 72 69 6f 5f 6d 6f 64 65 6c 6f 5f 44 4f 43 28 29 } //1 Public Sub diretorio_modelo_DOC()
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_108{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 54 42 44 69 73 63 72 65 74 69 6f 6e 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub TBDiscretion_Change()
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 54 42 52 65 61 64 79 74 6f 43 61 73 65 77 6f 72 6b 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub TBReadytoCasework_Change()
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 50 72 65 42 69 6f 43 6f 70 79 32 28 29 } //2 Private Sub PreBioCopy2()
		$a_00_3 = {50 72 69 76 61 74 65 20 53 75 62 20 53 68 61 72 65 50 65 72 66 6f 72 6d 61 6e 63 65 31 28 29 } //2 Private Sub SharePerformance1()
		$a_00_4 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 71 75 61 63 6b 69 74 2e 63 6f 6d } //2 https://www.quackit.com
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}
rule _#ASRWin32ApiMacroExclusion_109{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 63 72 65 61 74 65 4e 61 6d 65 64 52 61 6e 67 65 73 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 20 3d 20 } //1 Attribute createNamedRanges.VB_ProcData.VB_Invoke_Func = 
		$a_00_1 = {63 6f 6c 4e 6f 20 3d 20 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 43 6f 6c 75 6d 6e 73 28 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 43 6f 6c 75 6d 6e 73 2e 43 6f 75 6e 74 29 2e 43 6f 6c 75 6d 6e 20 2b 20 31 } //1 colNo = range("zDlgPeriods").Columns(range("zDlgPeriods").Columns.Count).Column + 1
		$a_00_2 = {66 69 6c 65 6e 61 6d 65 20 3d 20 45 6e 76 69 72 6f 6e 24 } //1 filename = Environ$
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_110{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 74 6f 6f 6c 73 5f 47 65 74 45 78 63 65 70 74 69 6f 6e 49 6e 66 6f 56 42 } //1 Dtools_GetExceptionInfoVB
		$a_00_1 = {4d 6f 73 74 20 6f 66 20 74 68 65 20 63 61 6c 6c 73 20 68 65 72 65 20 61 72 65 20 73 69 6d 70 6c 79 20 77 72 61 70 70 65 72 73 20 66 6f 72 20 63 61 6c 6c 69 6e 67 20 69 6e 74 6f 20 44 74 6f 6f 6c 73 2e 78 6c 6c } //1 Most of the calls here are simply wrappers for calling into Dtools.xll
		$a_00_2 = {44 74 6f 6f 6c 73 5f 52 69 73 6b 46 69 6e 64 49 6e 70 75 74 73 41 6e 64 4f 75 74 70 75 74 73 } //1 Dtools_RiskFindInputsAndOutputs
		$a_00_3 = {57 72 61 70 70 65 72 73 20 66 6f 72 20 44 74 6f 6f 6c 73 20 46 75 6e 63 74 69 6f 6e 73 } //1 Wrappers for Dtools Functions
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_111{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 58 4c 50 79 44 4c 4c 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 78 6c 77 69 6e 67 73 36 34 2d 30 2e 31 35 2e 31 30 2e 64 6c 6c 22 } //2 Const XLPyDLLName As String = "xlwings64-0.15.10.dll"
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 58 4c 57 49 4e 47 53 5f 56 45 52 53 49 4f 4e 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 30 2e 31 35 2e 31 30 22 } //2 Public Const XLWINGS_VERSION As String = "0.15.10"
		$a_00_2 = {50 79 2e 53 65 74 41 74 74 72 20 50 79 2e 4d 6f 64 75 6c 65 28 22 78 6c 77 69 6e 67 73 2e 5f 78 6c 77 69 6e 64 6f 77 73 22 29 2c 20 22 42 4f 4f 4b 5f 43 41 4c 4c 45 52 22 } //2 Py.SetAttr Py.Module("xlwings._xlwindows"), "BOOK_CALLER"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_112{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 73 61 70 70 72 64 31 35 6d 73 2e 72 65 64 6d 6f 6e 64 2e 63 6f 72 70 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 73 61 70 2f 62 63 2f 75 69 32 2f 66 6c 70 23 53 68 65 6c 6c 2d 68 6f 6d 65 } //1 https://sapprd15ms.redmond.corp.microsoft.com/sap/bc/ui2/flp#Shell-home
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 73 66 63 2e 68 6b 2f 65 6e 2f 52 65 67 75 6c 61 74 6f 72 79 2d 66 75 6e 63 74 69 6f 6e 73 2f 50 72 6f 64 75 63 74 73 2f 4c 69 73 74 2d 6f 66 2d 45 53 47 2d 66 75 6e 64 73 } //1 https://www.sfc.hk/en/Regulatory-functions/Products/List-of-ESG-funds
		$a_00_2 = {50 75 62 6c 69 63 20 53 75 62 20 53 65 6c 65 6e 69 75 6d 28 29 } //1 Public Sub Selenium()
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_113{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {55 50 53 20 50 61 73 73 61 67 65 73 20 66 72 6f 6d 20 45 4c 4e 2e 63 73 76 } //1 UPS Passages from ELN.csv
		$a_00_1 = {68 74 74 70 3a 2f 2f 65 78 63 65 6c 2d 6d 61 6c 69 6e 2e 63 6f 6d } //1 http://excel-malin.com
		$a_00_2 = {49 66 20 6e 6f 6d 5f 70 63 20 4c 69 6b 65 20 22 53 4c 48 2a 22 20 54 68 65 6e 20 72 65 74 6f 75 72 6e 65 5f 53 69 74 65 20 3d 20 22 55 50 53 20 53 6c 6f 75 67 68 22 } //1 If nom_pc Like "SLH*" Then retourne_Site = "UPS Slough"
		$a_00_3 = {49 66 20 6e 6f 6d 5f 70 63 20 4c 69 6b 65 20 22 42 45 4c 2a 22 20 54 68 65 6e 20 72 65 74 6f 75 72 6e 65 5f 53 69 74 65 20 3d 20 22 55 50 53 20 42 72 61 69 6e 65 22 } //1 If nom_pc Like "BEL*" Then retourne_Site = "UPS Braine"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_114{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 61 74 68 4e 61 6d 65 4f 75 74 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 30 31 5f 46 41 55 46 2d 46 65 68 6c 65 72 5c 22 } //2 PathNameOut = Application.ActiveWorkbook.Path & "\01_FAUF-Fehler\"
		$a_00_1 = {6f 70 66 6e 20 3d 20 22 46 41 55 46 5f 46 65 68 6c 65 72 5f 22 20 26 20 52 69 67 68 74 24 28 54 4d 50 2c 20 32 29 } //2 opfn = "FAUF_Fehler_" & Right$(TMP, 2)
		$a_00_2 = {2e 53 75 62 6a 65 63 74 20 3d 20 22 42 44 45 20 46 65 68 6c 65 72 6d 6f 6e 69 74 6f 72 22 } //2 .Subject = "BDE Fehlermonitor"
		$a_00_3 = {43 4c 4d 53 28 31 29 20 3d 20 22 46 65 68 6c 65 72 64 61 74 75 6d 22 } //2 CLMS(1) = "Fehlerdatum"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_115{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 69 6d 20 77 73 5f 5a 75 6f 72 64 6e 75 6e 67 20 41 73 20 57 6f 72 6b 73 68 65 65 74 } //1 Dim ws_Zuordnung As Worksheet
		$a_00_1 = {53 65 74 20 77 73 5f 5a 75 6f 72 64 6e 75 6e 67 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 5a 75 6f 72 64 6e 75 6e 67 22 29 } //1 Set ws_Zuordnung = ActiveWorkbook.Worksheets("Zuordnung")
		$a_00_2 = {77 73 5f 5a 75 6f 72 64 6e 75 6e 67 2e 52 61 6e 67 65 28 22 42 31 22 29 20 3d 20 44 61 74 65 } //1 ws_Zuordnung.Range("B1") = Date
		$a_00_3 = {53 65 74 20 72 65 73 20 3d 20 77 73 5f 5a 75 6f 72 64 6e 75 6e 67 2e 52 61 6e 67 65 28 22 41 31 3a 41 31 30 30 30 30 22 29 } //1 Set res = ws_Zuordnung.Range("A1:A10000")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_116{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 45 72 72 2e 4e 75 6d 62 65 72 20 26 20 22 20 22 20 26 20 45 72 72 2e 44 65 73 63 72 69 70 74 69 6f 6e 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 22 49 54 47 20 44 65 73 69 67 6e 20 7c 20 41 64 64 44 65 73 69 67 6e 50 67 22 } //2 MsgBox Err.Number & " " & Err.Description, vbCritical, "ITG Design | AddDesignPg"
		$a_00_1 = {53 65 74 20 76 69 73 4d 73 74 72 20 3d 20 76 69 73 4d 73 74 72 73 2e 49 74 65 6d 28 22 54 72 61 6e 73 70 53 69 74 65 22 29 } //2 Set visMstr = visMstrs.Item("TranspSite")
		$a_00_2 = {53 65 74 20 76 69 73 4d 73 74 72 20 3d 20 76 69 73 4d 73 74 72 73 2e 49 74 65 6d 28 22 43 4b 54 44 65 6d 61 72 6b 22 29 } //2 Set visMstr = visMstrs.Item("CKTDemark")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_117{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 75 74 68 6f 72 20 2d 20 50 72 61 73 68 61 6e 74 20 44 65 73 68 70 61 6e 64 65 } //1 Author - Prashant Deshpande
		$a_00_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 4e 61 6d 65 73 2e 61 64 64 20 6e 61 6d 65 3a 3d 22 50 6f 70 43 61 63 68 65 5f 47 4c 5f 49 4e 54 45 52 46 41 43 45 5f 52 45 46 45 52 45 4e 43 45 37 22 } //1 Application.ActiveWorkbook.Names.add name:="PopCache_GL_INTERFACE_REFERENCE7"
		$a_00_2 = {43 4c 41 53 53 3a 42 6e 65 56 42 41 50 61 72 61 6d 65 74 65 72 } //1 CLASS:BneVBAParameter
		$a_00_3 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 4c 4f 47 5f 53 48 45 45 54 20 3d 20 22 42 6e 65 4c 6f 67 22 } //1 Private Const LOG_SHEET = "BneLog"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_118{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 5a 6f 74 65 72 6f 49 6e 73 65 72 74 42 69 62 6c 69 6f 67 72 61 70 68 79 28 29 } //1 Public Sub ZoteroInsertBibliography()
		$a_00_1 = {53 75 62 20 5a 6f 74 65 72 6f 43 6f 6d 6d 61 6e 64 28 63 6d 64 20 41 73 20 53 74 72 69 6e 67 2c 20 62 72 69 6e 67 54 6f 46 72 6f 6e 74 20 41 73 20 42 6f 6f 6c 65 61 6e 29 } //1 Sub ZoteroCommand(cmd As String, bringToFront As Boolean)
		$a_00_2 = {61 70 70 4e 61 6d 65 73 28 31 29 20 3d 20 22 5a 6f 74 65 72 6f 22 } //1 appNames(1) = "Zotero"
		$a_00_3 = {43 61 6c 6c 20 5a 6f 74 65 72 6f 43 6f 6d 6d 61 6e 64 28 22 61 64 64 45 64 69 74 43 69 74 61 74 69 6f 6e 22 2c 20 54 72 75 65 29 } //1 Call ZoteroCommand("addEditCitation", True)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_119{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {6e 61 6d 65 3d 22 79 69 65 6c 64 62 6f 6f 6b 61 64 64 69 6e 22 } //3 name="yieldbookaddin"
		$a_00_1 = {64 65 73 63 72 69 70 74 69 6f 6e 3d 22 79 69 65 6c 64 20 62 6f 6f 6b 20 65 78 63 65 6c 20 61 64 64 2d 69 6e 22 } //3 description="yield book excel add-in"
		$a_00_2 = {22 6c 6f 73 73 20 73 63 65 6e 61 72 69 6f 20 64 65 66 69 6e 69 74 69 6f 6e 22 } //1 "loss scenario definition"
		$a_00_3 = {22 73 63 65 6e 61 72 69 6f 20 61 6e 61 6c 79 73 69 73 20 66 75 6e 63 74 69 6f 6e 20 62 75 69 6c 64 65 72 22 } //1 "scenario analysis function builder"
		$a_00_4 = {22 70 79 20 66 75 6e 63 74 69 6f 6e 20 62 75 69 6c 64 65 72 22 } //1 "py function builder"
		$a_00_5 = {22 65 73 67 20 64 61 74 61 22 } //1 "esg data"
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_120{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 43 72 65 61 74 65 54 65 61 6d 73 4d 43 44 52 65 70 6f 72 74 28 70 70 61 70 70 20 41 73 20 4f 62 6a 65 63 74 2c 20 70 70 70 72 65 73 20 41 73 20 4f 62 6a 65 63 74 29 } //2 Sub CreateTeamsMCDReport(ppapp As Object, pppres As Object)
		$a_00_1 = {53 65 74 20 6d 6f 72 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 56 6f 69 63 65 20 44 61 74 61 22 29 2e 43 65 6c 6c 73 28 63 6f 75 6e 74 65 72 2c 20 31 29 } //2 Set more = Worksheets("Voice Data").Cells(counter, 1)
		$a_00_2 = {41 63 74 69 76 65 53 68 65 65 74 2e 43 68 61 72 74 4f 62 6a 65 63 74 73 28 22 43 6f 73 74 53 61 76 69 6e 67 73 43 68 61 72 74 22 29 2e 41 63 74 69 76 61 74 65 } //2 ActiveSheet.ChartObjects("CostSavingsChart").Activate
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_121{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 4c 6f 61 64 4d 61 74 68 54 79 70 65 43 6f 6d 6d 61 6e 64 73 28 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //1 Public Function LoadMathTypeCommands() As Boolean
		$a_00_1 = {4f 70 65 6e 73 20 74 68 65 20 4d 61 74 68 54 79 70 65 20 48 65 6c 70 20 66 69 6c 65 20 74 6f 20 61 20 70 61 72 74 69 63 75 6c 61 72 20 74 6f 70 69 63 } //1 Opens the MathType Help file to a particular topic
		$a_00_2 = {66 6f 6c 64 65 72 20 3d 20 47 65 74 4d 61 74 68 54 79 70 65 44 69 72 20 26 20 22 3a 22 } //1 folder = GetMathTypeDir & ":"
		$a_00_3 = {6c 6f 67 46 69 6c 65 4e 61 6d 65 20 3d 20 22 4d 54 5f 56 42 41 5f 41 73 73 65 72 74 73 2e 6c 6f 67 22 } //1 logFileName = "MT_VBA_Asserts.log"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_122{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {47 6c 6f 62 61 6c 20 6d 63 6f 6c 43 42 52 4d 53 68 65 65 74 73 20 41 73 20 63 6f 6c 43 42 52 4d 53 68 65 65 74 73 } //2 Global mcolCBRMSheets As colCBRMSheets
		$a_00_1 = {4c 65 6e 28 53 68 65 65 74 73 28 6d 73 74 72 57 6f 72 6b 73 68 65 65 74 29 2e 43 65 6c 6c 73 28 6c 52 6f 77 2c 20 6d 69 6e 74 41 73 73 65 74 49 44 43 6f 6c 29 2e 56 61 6c 75 65 29 } //2 Len(Sheets(mstrWorksheet).Cells(lRow, mintAssetIDCol).Value)
		$a_00_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 41 64 64 28 6f 62 6a 43 61 6c 49 74 65 6d 20 41 73 20 63 6c 73 43 61 6c 49 74 65 6d 2c 20 4f 70 74 69 6f 6e 61 6c 20 73 4b 65 79 20 41 73 20 53 74 72 69 6e 67 29 } //2 Public Function Add(objCalItem As clsCalItem, Optional sKey As String)
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_123{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 53 45 52 56 4c 45 54 5f 50 41 54 48 20 3d 20 22 68 74 74 70 3a 2f 2f 61 64 65 6c 70 68 69 2e 70 6f 69 73 65 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 6c 6f 63 61 6c 3a 38 30 2f 6f 61 5f 73 65 72 76 6c 65 74 73 2f 22 } //2 Const SERVLET_PATH = "http://adelphi.poise.homeoffice.local:80/oa_servlets/"
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 49 56 42 53 41 58 45 72 72 6f 72 48 61 6e 64 6c 65 72 5f 69 67 6e 6f 72 61 62 6c 65 57 61 72 6e 69 6e 67 } //2 Private Sub IVBSAXErrorHandler_ignorableWarning
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 49 56 42 53 41 58 43 6f 6e 74 65 6e 74 48 61 6e 64 6c 65 72 5f 73 74 61 72 74 45 6c 65 6d 65 6e 74 } //2 Private Sub IVBSAXContentHandler_startElement
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_124{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 76 62 43 6f 6d 70 20 3d 20 76 62 50 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 45 52 44 5f 4d 6f 64 75 6c 65 22 29 } //1 Set vbComp = vbP.VBComponents("ERD_Module")
		$a_00_1 = {6d 61 69 6e 46 69 6c 65 50 61 74 68 20 3d 20 6d 61 69 6e 46 69 6c 65 50 61 74 68 20 2b 20 22 5c 45 52 44 5f 4d 6f 64 75 6c 65 22 } //1 mainFilePath = mainFilePath + "\ERD_Module"
		$a_00_2 = {76 62 43 6f 6d 70 2e 4e 61 6d 65 20 3d 20 22 45 52 44 5f 4d 6f 64 75 6c 65 22 } //1 vbComp.Name = "ERD_Module"
		$a_00_3 = {4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 43 72 65 61 74 65 45 52 44 } //1 On Error GoTo CreateERD
		$a_00_4 = {4d 73 67 42 6f 78 20 22 43 72 65 61 74 65 20 45 52 44 20 66 61 69 6c 65 64 22 } //1 MsgBox "Create ERD failed"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_125{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 66 2e 54 6f 70 20 3d 20 41 63 74 69 76 65 50 72 65 73 65 6e 74 61 74 69 6f 6e 2e 53 6c 69 64 65 4d 61 73 74 65 72 2e 53 68 61 70 65 73 28 22 63 68 46 72 65 65 7a 65 22 29 2e 54 6f 70 } //1 cf.Top = ActivePresentation.SlideMaster.Shapes("chFreeze").Top
		$a_00_1 = {43 61 6c 6c 20 75 70 64 61 74 65 5f 54 69 6d 65 6c 69 6e 65 28 43 44 61 74 65 28 22 31 2d 4e 6f 76 2d 32 30 31 36 22 29 2c 20 31 2c 20 46 61 6c 73 65 2c 20 39 29 } //1 Call update_Timeline(CDate("1-Nov-2016"), 1, False, 9)
		$a_00_2 = {41 63 74 69 76 65 50 72 65 73 65 6e 74 61 74 69 6f 6e 2e 53 6c 69 64 65 4d 61 73 74 65 72 2e 53 68 61 70 65 73 28 22 63 68 46 72 65 65 7a 65 22 29 2e 43 6f 70 79 } //1 ActivePresentation.SlideMaster.Shapes("chFreeze").Copy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_126{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 61 62 6c 65 73 2e 41 64 64 20 28 22 53 46 52 20 63 75 73 74 6f 6d 65 72 20 6e 6f 74 65 73 22 29 } //1 tables.Add ("SFR customer notes")
		$a_00_1 = {45 78 65 63 75 74 65 20 67 65 74 73 66 72 2e 70 79 2c 20 77 68 69 63 68 20 6f 70 65 6e 20 61 20 62 72 6f 77 73 65 72 20 77 69 6e 64 6f 77 20 77 69 74 68 20 74 68 65 20 53 46 52 20 71 75 65 72 79 } //1 Execute getsfr.py, which open a browser window with the SFR query
		$a_00_2 = {43 68 65 63 6b 20 69 66 20 53 46 52 20 6e 75 6d 62 65 72 73 20 68 61 76 65 20 62 65 65 6e 20 69 6d 70 6f 72 74 65 64 } //1 Check if SFR numbers have been imported
		$a_00_3 = {53 65 74 20 73 66 72 53 68 65 65 74 20 3d 20 53 68 65 65 74 73 28 22 53 46 52 73 22 29 } //1 Set sfrSheet = Sheets("SFRs")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_127{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 22 43 31 3a 43 22 20 26 20 6c 61 73 74 72 6f 77 29 2e 46 6f 72 6d 75 6c 61 52 31 43 31 20 3d 20 22 53 74 61 66 66 20 50 61 79 72 6f 6c 6c 20 28 53 47 29 22 } //1 Range("C1:C" & lastrow).FormulaR1C1 = "Staff Payroll (SG)"
		$a_00_1 = {52 61 6e 67 65 28 22 43 31 3a 43 22 20 26 20 6c 61 73 74 72 6f 77 29 2e 46 6f 72 6d 75 6c 61 52 31 43 31 20 3d 20 22 4d 41 4e 41 47 45 4d 45 4e 54 20 50 41 59 52 4f 4c 4c 20 28 53 47 29 22 } //1 Range("C1:C" & lastrow).FormulaR1C1 = "MANAGEMENT PAYROLL (SG)"
		$a_00_2 = {53 75 62 20 53 74 61 66 66 53 61 6c 45 47 69 72 6f 50 4c 55 53 28 29 } //1 Sub StaffSalEGiroPLUS()
		$a_00_3 = {53 75 62 20 4d 67 6d 74 53 61 6c 45 47 69 72 6f 50 4c 55 53 28 29 } //1 Sub MgmtSalEGiroPLUS()
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_128{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 66 6f 72 74 65 73 67 6c 6f 62 61 6c 2e 63 6f 6d } //2 https://www.fortesglobal.com
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 69 73 7a 2e 6e 6c } //2 http://www.fisz.nl
		$a_00_2 = {73 74 72 4c 6f 63 61 6c 65 28 53 55 50 50 4f 52 54 4d 41 49 4c 54 4f 29 20 3d 20 22 6d 61 69 6c 74 6f 3a 73 75 70 70 6f 72 74 40 66 6f 72 74 65 73 2e 6e 6c 22 } //2 strLocale(SUPPORTMAILTO) = "mailto:support@fortes.nl"
		$a_00_3 = {73 74 72 4c 6f 63 61 6c 65 28 49 4e 53 45 52 54 4b 45 59 57 4f 52 44 53 55 52 4c 29 20 3d 20 22 69 6e 73 65 72 74 69 6e 67 5f 70 72 69 6e 63 69 70 61 6c 5f 74 6f 6f 6c 62 6f 78 5f 6b 65 2e 68 74 6d 22 } //2 strLocale(INSERTKEYWORDSURL) = "inserting_principal_toolbox_ke.htm"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_129{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {69 6e 76 6f 69 63 65 20 6e 75 6d 62 65 72 20 63 6f 6e 76 65 72 74 20 69 6e 20 55 70 70 61 72 20 43 61 73 65 20 20 65 6e 64 } //2 invoice number convert in Uppar Case  end
		$a_01_1 = {43 68 65 63 6b 20 50 49 4e 20 46 6f 72 6d 61 74 20 61 6e 64 20 63 6f 6e 76 65 72 74 20 69 6e 20 55 70 70 61 72 20 43 61 73 65 20 53 74 61 72 74 } //2 Check PIN Format and convert in Uppar Case Start
		$a_01_2 = {42 61 73 65 20 6f 6e 20 54 61 78 61 62 6c 65 20 76 61 6c 75 65 20 52 65 6c 65 76 61 6e 74 20 49 6e 76 6f 69 63 65 20 44 61 74 65 } //2 Base on Taxable value Relevant Invoice Date
		$a_01_3 = {43 68 65 63 6b 20 52 65 6c 65 76 61 6e 74 20 49 6e 76 6f 69 63 65 20 44 61 74 65 20 46 6f 72 6d 61 74 } //2 Check Relevant Invoice Date Format
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_130{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 54 79 70 65 20 44 74 6f 6f 6c 73 50 72 6f 66 69 6c 65 53 74 61 74 73 } //1 Private Type DtoolsProfileStats
		$a_00_1 = {72 63 20 3d 20 44 74 6f 6f 6c 73 5f 47 65 74 44 74 6f 6f 6c 73 49 6e 73 74 61 6e 63 65 49 64 28 29 } //1 rc = Dtools_GetDtoolsInstanceId()
		$a_00_2 = {43 68 65 63 6b 20 69 66 20 44 74 6f 6f 6c 73 20 69 73 20 61 6c 72 65 61 64 79 20 6c 6f 61 64 65 64 20 69 6e 20 74 68 65 20 45 78 63 65 6c 20 61 70 70 6c 69 63 61 74 69 6f 6e } //1 Check if Dtools is already loaded in the Excel application
		$a_00_3 = {72 63 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 45 76 61 6c 75 61 74 65 28 22 3d 44 74 6f 6f 6c 73 56 65 72 73 69 6f 6e 28 29 22 29 } //1 rc = Application.Evaluate("=DtoolsVersion()")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_131{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 65 6c 65 63 74 69 6f 6e 2e 41 75 74 6f 46 69 6c 74 65 72 20 66 69 65 6c 64 3a 3d 32 2c 20 43 72 69 74 65 72 69 61 31 3a 3d 63 72 69 74 65 72 69 61 31 5f 76 61 6c 75 65 } //2 Selection.AutoFilter field:=2, Criteria1:=criteria1_value
		$a_01_1 = {53 65 6c 65 63 74 69 6f 6e 2e 41 75 74 6f 46 69 6c 74 65 72 20 66 69 65 6c 64 3a 3d 33 2c 20 43 72 69 74 65 72 69 61 31 3a 3d 63 72 69 74 65 72 69 61 32 5f 76 61 6c 75 65 } //2 Selection.AutoFilter field:=3, Criteria1:=criteria2_value
		$a_01_2 = {53 65 6c 65 63 74 69 6f 6e 2e 41 75 74 6f 46 69 6c 74 65 72 20 66 69 65 6c 64 3a 3d 34 2c 20 43 72 69 74 65 72 69 61 31 3a 3d 63 72 69 74 65 72 69 61 33 5f 76 61 6c 75 65 } //2 Selection.AutoFilter field:=4, Criteria1:=criteria3_value
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_132{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 42 45 78 31 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 42 45 78 41 6e 61 6c 79 7a 65 72 2e 78 6c 61 21 47 65 74 42 45 78 22 29 } //1 Set BEx1 = Application.Run("BExAnalyzer.xla!GetBEx")
		$a_00_1 = {53 65 74 20 6c 5f 63 6f 6e 74 72 6f 6c 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 2e 46 69 6e 64 43 6f 6e 74 72 6f 6c 28 54 61 67 3a 3d 22 44 46 57 46 69 6c 74 65 72 22 29 } //1 Set l_control = Application.CommandBars.FindControl(Tag:="DFWFilter")
		$a_00_2 = {53 68 65 65 74 32 2e 43 65 6c 6c 73 28 31 37 20 2b 20 28 32 20 2a 20 69 29 2c 20 32 39 29 2e 56 61 6c 75 65 20 3d 20 22 5a 43 4d 50 4f 5f 43 4f 4d 50 41 4e 59 22 } //1 Sheet2.Cells(17 + (2 * i), 29).Value = "ZCMPO_COMPANY"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_133{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 44 47 49 5f 53 4f 55 52 43 45 5f 45 53 54 49 4d 41 54 49 4f 4e 5f 53 48 45 45 54 5f 4e 41 4d 45 20 3d 20 22 45 66 66 6f 72 74 20 65 73 74 69 6d 61 74 69 6f 6e 73 22 } //2 Private Const DGI_SOURCE_ESTIMATION_SHEET_NAME = "Effort estimations"
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 44 47 49 5f 45 53 54 49 4d 41 54 49 4f 4e 5f 53 48 45 45 54 5f 4e 41 4d 45 20 3d 20 22 44 47 49 20 45 66 66 6f 72 74 20 65 73 74 69 6d 61 74 69 6f 6e 73 22 } //2 Private Const DGI_ESTIMATION_SHEET_NAME = "DGI Effort estimations"
		$a_00_2 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 67 65 74 44 67 69 45 73 74 69 6d 61 74 69 6f 6e 57 6f 72 6b 62 6f 6f 6b } //2 Private Function getDgiEstimationWorkbook
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_134{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 43 68 61 72 74 2e 43 68 61 72 74 54 69 74 6c 65 2e 54 65 78 74 20 3d 20 22 50 72 6f 64 75 63 74 69 6f 6e 20 2f 20 43 6f 6e 73 75 6d 70 74 69 6f 6e 22 20 26 20 22 20 75 70 20 74 6f 20 22 20 26 20 76 5a 61 65 68 6c 65 72 20 2a 20 32 34 20 26 20 22 20 68 22 } //2 ActiveChart.ChartTitle.Text = "Production / Consumption" & " up to " & vZaehler * 24 & " h"
		$a_00_1 = {41 63 74 69 76 65 43 68 61 72 74 2e 43 68 61 72 74 54 69 74 6c 65 2e 54 65 78 74 20 3d 20 22 50 72 6f 64 75 6b 74 69 6f 6e 20 2f 20 56 65 72 62 72 61 75 63 68 22 20 26 20 22 20 62 69 73 20 7a 75 20 22 20 26 20 76 5a 61 65 68 6c 65 72 20 2a 20 32 34 20 26 20 22 20 68 22 } //2 ActiveChart.ChartTitle.Text = "Produktion / Verbrauch" & " bis zu " & vZaehler * 24 & " h"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=2
 
}
rule _#ASRWin32ApiMacroExclusion_135{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {49 66 20 4e 6f 74 20 69 73 53 41 50 44 6f 63 28 44 6f 63 2e 4e 61 6d 65 29 20 54 68 65 6e } //1 If Not isSAPDoc(Doc.Name) Then
		$a_00_1 = {53 75 62 20 73 61 70 5f 67 65 74 4c 61 62 65 6c 28 63 6f 6e 74 72 6f 6c 20 41 73 20 49 52 69 62 62 6f 6e 43 6f 6e 74 72 6f 6c 2c 20 42 79 52 65 66 20 72 65 74 75 72 6e 65 64 56 61 6c 29 } //1 Sub sap_getLabel(control As IRibbonControl, ByRef returnedVal)
		$a_00_2 = {43 61 73 65 20 49 73 20 3d 20 22 53 41 50 47 72 6f 75 70 31 22 20 27 20 56 69 65 77 20 67 72 6f 75 70 } //1 Case Is = "SAPGroup1" ' View group
		$a_00_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 69 73 53 41 50 44 6f 63 28 6b 65 79 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //1 Public Function isSAPDoc(key As String) As Boolean
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_136{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 79 66 69 6c 65 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 70 61 74 68 20 26 20 22 5c 54 58 54 50 44 46 2e 74 78 74 22 } //1 myfile = ThisWorkbook.path & "\TXTPDF.txt"
		$a_00_1 = {44 69 6d 20 64 65 6c 6c 5f 6f 72 64 65 72 5f 6c 69 6e 65 5f 61 72 72 61 79 20 41 73 20 56 61 72 69 61 6e 74 } //1 Dim dell_order_line_array As Variant
		$a_00_2 = {64 65 6c 6c 6e 6f 20 3d 20 49 6e 53 74 72 28 55 43 61 73 65 28 74 65 78 74 6c 69 6e 65 29 2c 20 55 43 61 73 65 28 22 44 65 6c 6c 20 4f 72 64 65 72 20 4e 6f 3a 22 29 29 } //1 dellno = InStr(UCase(textline), UCase("Dell Order No:"))
		$a_00_3 = {4d 73 67 42 6f 78 20 22 53 75 63 63 65 73 73 3a 20 50 44 46 20 63 6f 6e 76 65 72 74 65 64 20 69 6e 74 6f 20 54 65 78 74 2e 22 } //1 MsgBox "Success: PDF converted into Text."
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_137{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 6d 61 63 72 6f 5f 73 68 74 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 45 78 74 72 61 5f 50 64 66 5f 44 61 74 61 22 29 } //2 Set macro_sht = ThisWorkbook.Worksheets("Extra_Pdf_Data")
		$a_00_1 = {6d 61 63 72 6f 5f 73 68 74 2e 43 65 6c 6c 73 28 69 2c 20 31 36 29 20 3d 20 22 59 6c 6d 31 30 20 2d 20 4e 6f 20 50 61 72 74 20 4e 75 6d 62 65 72 22 } //2 macro_sht.Cells(i, 16) = "Ylm10 - No Part Number"
		$a_00_2 = {6c 73 74 5f 70 75 72 71 74 79 5f 63 75 6e 74 20 3d 20 55 42 6f 75 6e 64 28 53 70 6c 69 74 28 73 70 6c 69 74 5f 70 61 67 65 28 69 29 2c 20 22 50 75 72 63 68 61 73 65 20 4f 72 64 65 72 20 51 75 61 6e 74 69 74 79 22 29 29 20 2d 20 31 } //2 lst_purqty_cunt = UBound(Split(split_page(i), "Purchase Order Quantity")) - 1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_138{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 65 76 65 6c 6f 70 65 64 20 62 79 20 4d 69 63 68 61 65 6c 20 45 69 66 66 6c 61 65 6e 64 65 72 20 2f 20 41 45 20 53 6f 66 74 77 61 72 65 20 53 6f 6c 75 74 69 6f 6e 73 } //5 Developed by Michael Eifflaender / AE Software Solutions
		$a_00_1 = {50 75 62 6c 69 63 20 74 4d 69 6c 65 73 74 6f 6e 65 73 28 35 30 30 30 29 20 41 73 20 54 6d 69 6c 65 73 74 6f 6e 65 } //2 Public tMilestones(5000) As Tmilestone
		$a_00_2 = {50 75 62 6c 69 63 20 6f 62 6a 50 50 54 20 41 73 20 4f 62 6a 65 63 74 20 27 50 6f 77 65 72 50 6f 69 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //2 Public objPPT As Object 'PowerPoint.Application
		$a_00_3 = {4d 73 67 42 6f 78 20 22 4e 6f 20 66 69 6c 65 73 20 73 65 6c 65 63 74 65 64 20 66 6f 72 20 61 6e 61 6c 79 73 69 73 22 } //2 MsgBox "No files selected for analysis"
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=11
 
}
rule _#ASRWin32ApiMacroExclusion_139{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 70 69 63 6f 6c 6d 65 6d 20 3d 20 70 69 63 6f 6c 6c 69 73 74 2e 49 74 65 6d 28 22 57 53 4c 44 43 54 50 50 49 48 32 22 29 } //1 Set picolmem = picollist.Item("WSLDCTPPIH2")
		$a_00_1 = {73 54 61 67 6e 61 6d 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 45 6e 74 72 79 20 53 68 65 65 74 22 29 2e 43 65 6c 6c 73 28 69 20 2b 20 34 2c 20 32 29 2e 54 65 78 74 } //1 sTagname = Worksheets("Entry Sheet").Cells(i + 4, 2).Text
		$a_00_2 = {57 72 69 74 65 20 74 6f 20 53 65 63 6f 6e 64 61 79 20 50 49 20 53 65 72 76 65 72 } //1 Write to Seconday PI Server
		$a_00_3 = {73 72 76 2e 50 49 50 6f 69 6e 74 73 28 73 54 61 67 6e 61 6d 65 29 2e 44 61 74 61 2e 55 70 64 61 74 65 56 61 6c 75 65 20 73 56 61 6c 75 65 2c 20 73 54 69 6d 65 } //1 srv.PIPoints(sTagname).Data.UpdateValue sValue, sTime
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_140{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 69 61 6c 6f 67 2e 54 69 74 6c 65 20 3d 20 22 53 65 6c 65 63 74 20 5a 44 4f 43 5a 49 50 31 20 45 78 70 6f 72 74 20 41 72 63 68 69 76 65 22 } //1 Dialog.Title = "Select ZDOCZIP1 Export Archive"
		$a_00_1 = {41 42 44 4b 41 4d 20 2d 20 6d 61 74 74 68 69 61 73 2e 6b 61 6e 7a 6c 65 72 40 61 6d 6d 61 6e 6e 2e 63 6f 6d 20 30 33 2e 31 31 2e 32 30 32 30 } //1 ABDKAM - matthias.kanzler@ammann.com 03.11.2020
		$a_00_2 = {5c 75 73 65 72 30 32 2e 61 6d 6d 61 6e 6e 2d 67 72 6f 75 70 2e 63 6f 6d 5c 55 73 65 72 44 61 74 61 5c 48 6f 6d 65 5c 41 42 44 5c 68 6f 6d 65 30 32 5c 41 42 44 4b 61 4d 5c 63 6f 6e 66 69 67 5c 64 65 73 6b 74 6f 70 5c 5a 44 4f 43 5a 49 50 31 5f 41 6e 70 61 73 73 75 6e 67 65 6e } //1 \user02.ammann-group.com\UserData\Home\ABD\home02\ABDKaM\config\desktop\ZDOCZIP1_Anpassungen
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_141{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //5 https://www.asap-utilities.com
		$a_00_1 = {70 5f 73 50 61 74 68 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 28 22 41 53 41 50 20 55 74 69 6c 69 74 69 65 73 2e 78 6c 61 6d 22 29 2e 50 61 74 68 } //2 p_sPath = Workbooks("ASAP Utilities.xlam").Path
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 27 41 53 41 50 20 55 74 69 6c 69 74 69 65 73 2e 78 6c 61 6d 27 21 41 53 41 50 52 75 6e 50 72 6f 63 5f 78 36 34 22 2c 20 6c 49 44 } //2 Application.Run "'ASAP Utilities.xlam'!ASAPRunProc_x64", lID
		$a_00_3 = {53 75 62 20 41 53 41 50 52 69 62 62 6f 6e 5f 49 6e 69 74 69 61 6c 69 7a 65 28 72 69 62 62 6f 6e 20 41 73 20 49 52 69 62 62 6f 6e 55 49 29 } //2 Sub ASAPRibbon_Initialize(ribbon As IRibbonUI)
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=11
 
}
rule _#ASRWin32ApiMacroExclusion_142{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 54 4c 43 6f 6d 62 6f 42 6f 78 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub TLComboBox_Change()
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 52 65 6a 43 61 70 74 75 72 65 42 75 74 74 6f 6e 5f 43 6c 69 63 6b 28 29 } //2 Private Sub RejCaptureButton_Click()
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 52 65 6a 45 6d 61 69 6c 54 78 74 42 6f 78 5f 43 68 61 6e 67 65 28 29 } //2 Private Sub RejEmailTxtBox_Change()
		$a_00_3 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 50 72 6f 64 75 63 74 69 76 69 74 79 22 29 2e 50 72 6f 74 65 63 74 20 50 61 73 73 77 6f 72 64 3a 3d 22 52 61 6d 65 73 65 73 22 } //1 ActiveWorkbook.Sheets("Productivity").Protect Password:="Rameses"
		$a_00_4 = {53 75 62 20 77 69 70 65 61 6c 6c 28 29 } //1 Sub wipeall()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_143{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {47 6c 6f 62 61 6c 20 43 6f 6e 73 74 20 58 4c 53 54 41 52 54 5f 46 49 4c 45 5f 30 31 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 6d 65 69 6a 62 75 72 67 46 75 6e 63 74 69 65 73 2e 78 6c 61 6d 22 } //1 Global Const XLSTART_FILE_01 As String = "meijburgFuncties.xlam"
		$a_00_1 = {47 6c 6f 62 61 6c 20 43 6f 6e 73 74 20 58 4c 53 54 41 52 54 5f 46 49 4c 45 5f 30 32 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 44 42 5f 53 74 6f 72 61 67 65 2e 78 6c 61 6d 22 } //1 Global Const XLSTART_FILE_02 As String = "DB_Storage.xlam"
		$a_00_2 = {57 42 2e 43 65 6c 6c 73 2e 52 65 70 6c 61 63 65 20 77 68 61 74 3a 3d 22 6d 62 46 75 6e 63 74 69 65 73 2e 78 6c 61 6d 22 2c 20 52 65 70 6c 61 63 65 6d 65 6e 74 3a 3d 22 4d 4d 32 2e 30 2e 78 6c 61 6d 22 } //1 WB.Cells.Replace what:="mbFuncties.xlam", Replacement:="MM2.0.xlam"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_144{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 61 6c 63 75 6c 61 74 69 6f 6e 20 3d 20 78 6c 43 61 6c 63 75 6c 61 74 69 6f 6e 41 75 74 6f 6d 61 74 69 63 } //2 Application.Calculation = xlCalculationAutomatic
		$a_00_1 = {49 66 20 62 6f 6f 6c 54 65 6d 70 20 3c 3e 20 53 52 41 63 74 69 76 61 74 69 6f 6e 42 6c 6f 63 6b 65 64 20 54 68 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 61 6c 63 75 6c 61 74 65 46 75 6c 6c 52 65 62 75 69 6c 64 } //2 If boolTemp <> SRActivationBlocked Then Application.CalculateFullRebuild
		$a_00_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 49 6e 70 75 74 22 29 2e 43 65 6c 6c 73 28 31 2c 20 31 29 2e 46 6f 72 6d 75 6c 61 20 3d 20 22 3d 53 74 6f 72 61 67 65 43 61 6c 63 28 4e 6f 77 29 22 } //2 ThisWorkbook.Sheets("Input").Cells(1, 1).Formula = "=StorageCalc(Now)"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_145{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {5c 73 74 6c 66 69 6c 65 30 31 2e 69 6e 74 65 6c 6c 69 67 2e 6c 6f 63 61 6c 5c 44 41 54 41 5c 4c 45 47 41 43 59 5c 53 54 4c 2d 45 4e 47 32 5c 50 5f 44 72 69 76 65 5c 50 52 4f 50 4f 53 41 4c 5c 5a 53 79 73 74 65 6d 50 72 6f 70 } //2 \stlfile01.intellig.local\DATA\LEGACY\STL-ENG2\P_Drive\PROPOSAL\ZSystemProp
		$a_00_1 = {5c 77 63 6e 61 73 30 31 2e 69 6e 74 65 6c 6c 69 67 2e 6c 6f 63 61 6c 5c 69 6e 74 65 6c 6c 69 67 72 61 74 65 64 5c 44 65 70 74 5c 50 72 6f 6a 65 63 74 73 } //2 \wcnas01.intellig.local\intelligrated\Dept\Projects
		$a_00_2 = {5c 73 74 6c 66 69 6c 65 30 31 5c 44 41 54 41 5c 4c 45 47 41 43 59 5c 53 54 4c 2d 41 52 43 5c 53 74 2e 20 4c 6f 75 69 73 20 4c 65 67 61 63 79 20 50 72 6f 6a 65 63 74 20 44 69 72 65 63 74 6f 72 79 } //2 \stlfile01\DATA\LEGACY\STL-ARC\St. Louis Legacy Project Directory
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=2
 
}
rule _#ASRWin32ApiMacroExclusion_146{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 65 74 73 28 22 50 4c 2d 42 53 20 49 6d 70 61 63 74 22 29 2e 53 65 6c 65 63 74 } //1 Sheets("PL-BS Impact").Select
		$a_00_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 4e 61 6d 65 20 3d 20 22 4f 50 45 58 20 49 6d 70 61 63 74 22 } //1 ActiveSheet.Name = "OPEX Impact"
		$a_00_2 = {63 75 72 72 65 6e 74 43 65 6c 6c 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 4a 45 54 45 4d 50 4c 41 54 45 22 29 2e 43 65 6c 6c 73 28 61 63 74 69 76 65 43 65 6c 6c 52 6f 77 2c 20 31 31 29 2e 56 61 6c 75 65 } //1 currentCell = ThisWorkbook.Worksheets("JETEMPLATE").Cells(activeCellRow, 11).Value
		$a_00_3 = {44 69 6d 20 4e 62 4c 69 67 6e 65 2c 20 44 65 72 4c 69 67 6e 65 2c 20 49 6e 73 65 72 74 4c 69 67 6e 65 20 41 73 20 53 74 72 69 6e 67 } //1 Dim NbLigne, DerLigne, InsertLigne As String
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_147{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 22 59 6f 75 20 68 61 76 65 20 73 65 6c 65 63 74 65 64 20 74 6f 20 72 75 6e 20 74 68 65 20 41 45 52 4d 4f 44 20 50 72 69 6d 65 20 6d 6f 64 65 6c 2c 20 62 75 74 20 74 68 65 20 53 63 72 65 65 6e 69 6e 67 20 54 6f 6f 6c 20 63 61 6e 6e 6f 74 22 } //1 MsgBox "You have selected to run the AERMOD Prime model, but the Screening Tool cannot"
		$a_00_1 = {43 68 44 72 69 76 65 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 70 61 74 68 20 26 20 22 5c 53 43 52 45 45 4e 5c 41 45 52 4d 4f 44 50 52 49 4d 45 5c 22 } //1 ChDrive ActiveWorkbook.path & "\SCREEN\AERMODPRIME\"
		$a_00_2 = {44 69 6d 20 41 45 52 4d 4f 44 50 52 49 4d 45 66 6f 6c 64 65 72 20 41 73 20 53 74 72 69 6e 67 } //1 Dim AERMODPRIMEfolder As String
		$a_00_3 = {41 51 4d 41 55 20 53 43 52 45 45 4e 49 4e 47 20 54 4f 4f 4c } //1 AQMAU SCREENING TOOL
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_148{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 64 20 62 79 20 44 6f 75 67 20 52 6f 62 62 69 6e 73 20 2d 20 64 6b 72 40 6d 76 70 73 2e 6f 72 67 } //1 Created by Doug Robbins - dkr@mvps.org
		$a_00_1 = {6c 6e 67 43 6f 75 6e 74 20 3d 20 56 61 6c 28 47 65 74 53 65 74 74 69 6e 67 28 22 41 6c 61 74 47 61 62 75 6e 67 6b 61 6e 22 2c 20 22 50 65 6d 61 6b 61 69 61 6e 22 2c 20 22 48 69 74 75 6e 67 22 29 29 } //1 lngCount = Val(GetSetting("AlatGabungkan", "Pemakaian", "Hitung"))
		$a_00_2 = {53 65 74 20 6f 49 74 65 6d 20 3d 20 6f 4f 75 74 6c 6f 6f 6b 41 70 70 2e 43 72 65 61 74 65 49 74 65 6d 46 72 6f 6d 54 65 6d 70 6c 61 74 65 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 22 5c 4d 65 72 67 65 54 6f 6f 6c 73 2e 6f 66 74 22 29 } //1 Set oItem = oOutlookApp.CreateItemFromTemplate(Application.StartupPath & "\MergeTools.oft")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_149{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 55 42 4b 45 59 20 3d 20 22 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 54 47 44 6f 63 58 2e 65 78 65 22 } //2 Public Const SUBKEY = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ITGDocX.exe"
		$a_00_1 = {49 66 20 4c 65 66 74 28 56 61 6c 75 65 4e 61 6d 65 2c 20 56 61 6c 75 65 6c 65 6e 29 20 3d 20 22 49 54 47 44 6f 63 58 50 61 74 68 22 20 54 68 65 6e } //2 If Left(ValueName, Valuelen) = "ITGDocXPath" Then
		$a_00_2 = {53 65 74 20 76 69 73 41 64 64 4f 6e 20 3d 20 56 69 73 69 6f 2e 41 64 64 6f 6e 73 2e 41 64 64 28 73 74 72 41 70 70 50 61 74 68 20 26 20 22 49 54 47 44 6f 63 58 2e 65 78 65 22 29 } //2 Set visAddOn = Visio.Addons.Add(strAppPath & "ITGDocX.exe")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_150{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 6c 5f 63 6f 6e 74 72 6f 6c 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 2e 46 69 6e 64 43 6f 6e 74 72 6f 6c 28 54 61 67 3a 3d 22 44 46 57 46 69 6c 74 65 72 22 29 } //1 Set l_control = Application.CommandBars.FindControl(Tag:="DFWFilter")
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 73 65 74 46 69 6c 74 65 72 56 69 73 69 62 69 6c 69 74 79 28 69 56 69 73 69 62 6c 65 20 41 73 20 42 6f 6f 6c 65 61 6e 29 } //1 Public Sub setFilterVisibility(iVisible As Boolean)
		$a_00_2 = {53 65 74 20 6c 53 68 61 70 65 20 3d 20 6c 53 68 65 65 74 2e 53 68 61 70 65 73 28 22 46 69 6c 74 65 72 41 22 29 } //1 Set lShape = lSheet.Shapes("FilterA")
		$a_00_3 = {53 65 74 20 6c 53 68 61 70 65 20 3d 20 6c 53 68 65 65 74 2e 53 68 61 70 65 73 28 22 49 6e 66 6f 41 22 29 } //1 Set lShape = lSheet.Shapes("InfoA")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_151{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 73 75 62 45 78 65 63 5f 70 73 53 65 6c 65 63 74 49 6e 76 65 73 74 69 73 73 65 6d 65 6e 74 28 69 64 48 79 70 6f 74 68 65 73 65 20 41 73 20 53 74 72 69 6e 67 2c 20 69 64 46 6f 6e 64 73 20 41 73 20 53 74 72 69 6e 67 29 } //2 Sub subExec_psSelectInvestissement(idHypothese As String, idFonds As String)
		$a_00_1 = {50 61 72 61 6d 65 74 65 72 73 28 22 40 70 72 6f 70 49 6e 76 65 73 74 69 73 73 65 6d 65 6e 74 22 29 } //2 Parameters("@propInvestissement")
		$a_00_2 = {50 61 72 61 6d 65 74 65 72 73 28 22 40 6c 62 48 79 70 6f 74 68 65 73 65 22 29 2e 56 61 6c 75 65 20 3d 20 69 64 48 79 70 6f 74 68 65 73 65 } //2 Parameters("@lbHypothese").Value = idHypothese
		$a_00_3 = {50 61 72 61 6d 65 74 65 72 73 28 22 40 6c 62 53 43 50 49 22 29 2e 56 61 6c 75 65 20 3d 20 69 64 46 6f 6e 64 73 } //2 Parameters("@lbSCPI").Value = idFonds
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_152{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 6f 77 65 72 70 6f 69 6e 74 73 68 6f 72 74 63 75 74 6d 61 6e 61 67 65 72 5f 6d 61 6e 61 67 65 73 68 6f 72 74 63 75 74 73 } //1 powerpointshortcutmanager_manageshortcuts
		$a_00_1 = {70 6f 77 65 72 70 6f 69 6e 74 73 68 6f 72 74 63 75 74 6d 61 6e 61 67 65 72 5f 73 65 74 74 69 6e 67 73 } //1 powerpointshortcutmanager_settings
		$a_00_2 = {70 6f 77 65 72 70 6f 69 6e 74 73 68 6f 72 74 63 75 74 6d 61 6e 61 67 65 72 5f 76 69 73 69 74 74 69 70 73 70 61 67 65 } //1 powerpointshortcutmanager_visittipspage
		$a_00_3 = {70 6f 77 65 72 70 6f 69 6e 74 73 68 6f 72 74 63 75 74 6d 61 6e 61 67 65 72 5f 61 62 6f 75 74 } //1 powerpointshortcutmanager_about
		$a_00_4 = {64 65 73 63 72 69 70 74 69 6f 6e 3d 22 73 68 6f 72 74 63 75 74 20 6d 61 6e 61 67 65 72 20 66 6f 72 20 70 6f 77 65 72 70 6f 69 6e 74 22 } //2 description="shortcut manager for powerpoint"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_153{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 77 73 74 68 5f 50 72 6f 6a 65 74 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 50 72 6f 6a 65 74 73 22 29 } //1 Set wsth_Projet = ThisWorkbook.Sheets("Projets")
		$a_00_1 = {53 65 74 20 77 73 74 68 5f 50 53 50 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 53 75 69 76 69 5f 50 53 50 22 29 } //1 Set wsth_PSP = ThisWorkbook.Sheets("Suivi_PSP")
		$a_00_2 = {53 65 74 20 77 73 74 68 5f 33 50 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 53 75 69 76 69 5f 33 50 22 29 } //1 Set wsth_3P = ThisWorkbook.Sheets("Suivi_3P")
		$a_00_3 = {6e 65 77 70 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 44 72 69 76 65 73 4d 61 70 69 6e 67 2e 78 6c 73 78 22 } //1 newpath = Environ("USERPROFILE") & "\DrivesMaping.xlsx"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_154{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 52 65 6c 65 61 73 65 50 61 74 68 5f 73 69 6d 63 6f 31 44 42 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 5c 5c 77 69 74 74 61 67 2e 6e 65 74 5c 64 66 73 5c 67 72 6f 75 70 73 5c 49 6e 66 6f 5c 73 65 72 76 6f 66 69 6c 65 73 5c 73 69 6d 63 6f 5c 4d 6f 74 6f 72 44 61 74 61 62 61 73 65 5f 46 69 72 6d 77 61 72 65 5c 22 } //2 Const ReleasePath_simco1DB As String = "\\wittag.net\dfs\groups\Info\servofiles\simco\MotorDatabase_Firmware\"
		$a_00_1 = {66 69 6c 65 2e 77 72 69 74 65 6c 69 6e 65 20 28 22 3c 2f 4d 6f 74 6f 72 44 61 74 61 62 61 73 65 3e 22 29 } //2 file.writeline ("</MotorDatabase>")
		$a_00_2 = {43 6f 6e 73 74 20 45 6e 64 61 74 46 69 6c 65 73 46 6f 6c 64 65 72 50 61 74 68 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 43 3a 5c 44 61 74 61 5c 54 65 6d 70 5c 22 } //2 Const EndatFilesFolderPath As String = "C:\Data\Temp\"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_155{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {46 69 6c 65 50 61 74 68 20 3d 20 22 47 3a 5c 54 45 41 4d 5c 4d 61 72 6b 65 74 20 4f 70 65 72 61 74 69 6f 6e 73 5c 53 54 4f 44 5c 4f 54 43 5c 50 72 69 63 65 20 44 61 74 61 62 61 73 65 20 56 34 2e 78 6c 73 62 22 } //1 FilePath = "G:\TEAM\Market Operations\STOD\OTC\Price Database V4.xlsb"
		$a_00_1 = {46 69 6c 65 53 74 72 20 3d 20 22 50 72 69 63 65 20 44 61 74 61 62 61 73 65 20 56 34 2e 78 6c 73 62 22 } //1 FileStr = "Price Database V4.xlsb"
		$a_00_2 = {4d 73 67 42 6f 78 20 22 50 6c 65 61 73 65 20 75 70 67 72 61 64 65 20 54 68 6f 6d 73 6f 6e 20 52 65 75 74 65 72 73 20 45 69 6b 6f 6e 20 45 78 63 65 6c 2e 22 } //1 MsgBox "Please upgrade Thomson Reuters Eikon Excel."
		$a_00_3 = {44 69 6d 20 47 46 53 45 4e 53 2c 20 47 46 53 4f 50 2c 20 45 43 45 4e 53 2c 20 45 43 4f 50 20 41 73 20 53 74 72 69 6e 67 } //1 Dim GFSENS, GFSOP, ECENS, ECOP As String
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_156{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 53 51 4c 5f 41 4d 4f 53 5f 44 42 5f 47 65 74 53 65 74 74 69 6e 67 73 28 29 } //1 Function SQL_AMOS_DB_GetSettings()
		$a_00_1 = {44 61 74 61 62 61 73 65 4e 61 6d 65 20 3d 20 22 41 6d 6f 73 22 20 27 20 45 6e 74 65 72 20 79 6f 75 72 20 64 61 74 61 62 61 73 65 20 6e 61 6d 65 20 68 65 72 65 } //1 DatabaseName = "Amos" ' Enter your database name here
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 53 51 4c 5f 41 4d 4f 53 5f 44 42 5f 47 65 74 41 63 63 65 73 73 4c 65 76 65 6c 73 28 73 74 72 55 73 65 72 6e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Function SQL_AMOS_DB_GetAccessLevels(strUsername As String)
		$a_00_3 = {53 51 4c 5f 41 4d 4f 53 5f 44 42 5f 50 6f 70 75 6c 61 74 65 5f 53 50 45 43 49 41 4c 5f 43 4f 4e 44 5f 55 53 52 46 52 4d 20 3d 20 22 6e 6f 74 66 6f 75 6e 64 22 } //1 SQL_AMOS_DB_Populate_SPECIAL_COND_USRFRM = "notfound"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_157{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 45 43 5f 4c 69 73 74 5f 53 65 61 72 63 68 2e 78 6c 61 6d 22 29 } //1 Workbooks("EC_List_Search.xlam")
		$a_00_1 = {53 4f 55 52 43 45 3a 20 68 74 74 70 3a 2f 2f 73 74 61 63 6b 6f 76 65 72 66 6c 6f 77 2e 63 6f 6d 2f 71 75 65 73 74 69 6f 6e 73 2f 31 34 37 33 38 33 33 30 2f 6f 66 66 69 63 65 2d 32 30 31 33 2d 65 78 63 65 6c 2d 70 75 74 69 6e 63 6c 69 70 62 6f 61 72 64 2d 69 73 2d 64 69 66 66 65 72 65 6e 74 } //1 SOURCE: http://stackoverflow.com/questions/14738330/office-2013-excel-putinclipboard-is-different
		$a_00_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 46 6f 6c 6c 6f 77 48 79 70 65 72 6c 69 6e 6b 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 78 63 65 6c 63 61 6d 70 75 73 2e 63 6f 6d 2f 6c 69 73 74 2d 73 65 61 72 63 68 2d 68 65 6c 70 22 } //1 ThisWorkbook.FollowHyperlink "https://www.excelcampus.com/list-search-help"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_158{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 74 72 48 65 6c 70 46 69 6c 65 20 3d 20 73 74 72 48 65 6c 70 46 69 6c 65 20 26 20 22 50 49 74 72 65 6e 64 58 4c 2e 48 4c 50 22 } //1 strHelpFile = strHelpFile & "PItrendXL.HLP"
		$a_00_1 = {50 75 62 6c 69 63 20 72 65 73 4f 62 6a 20 41 73 20 50 49 58 4c 54 57 49 5a 2e 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 73 } //1 Public resObj As PIXLTWIZ.ResourceStrings
		$a_00_2 = {50 75 62 6c 69 63 20 57 69 74 68 45 76 65 6e 74 73 20 6d 5f 6f 62 6a 50 49 41 72 63 44 43 20 41 73 20 50 49 44 41 54 41 41 43 43 45 53 53 2e 50 49 41 72 63 68 69 76 65 44 61 74 61 } //1 Public WithEvents m_objPIArcDC As PIDATAACCESS.PIArchiveData
		$a_00_3 = {49 66 20 49 6e 53 74 72 28 61 54 72 61 63 65 73 28 6c 6e 67 49 6e 64 65 78 29 2e 44 61 74 61 53 6f 75 72 63 65 4e 61 6d 65 2c 20 22 50 49 45 78 63 65 6c 44 61 74 61 22 29 } //1 If InStr(aTraces(lngIndex).DataSourceName, "PIExcelData")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_159{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 44 69 65 73 65 41 72 62 65 69 74 73 6d 61 70 70 65 22 } //2 Attribute VB_Name = "DieseArbeitsmappe"
		$a_00_1 = {57 6f 72 6b 73 68 65 65 74 73 28 22 45 78 70 6f 72 74 5f 53 41 50 22 29 2e 43 65 6c 6c 73 2e 43 6c 65 61 72 } //2 Worksheets("Export_SAP").Cells.Clear
		$a_00_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 43 6f 6e 74 69 66 6f 72 6d 22 29 2e 55 6e 70 72 6f 74 65 63 74 } //2 ThisWorkbook.Sheets("Contiform").Unprotect
		$a_00_3 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 43 6f 6e 74 69 66 65 65 64 22 29 2e 55 6e 70 72 6f 74 65 63 74 } //2 ThisWorkbook.Sheets("Contifeed").Unprotect
		$a_00_4 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 41 69 72 43 6f 22 29 2e 55 6e 70 72 6f 74 65 63 74 } //2 ThisWorkbook.Sheets("AirCo").Unprotect
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_160{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 52 45 47 5f 50 41 54 48 20 3d 20 22 53 6f 66 74 77 61 72 65 5c 4d 49 53 20 41 47 5c 50 4c 41 49 4e 5c 22 } //1 Public Const REG_PATH = "Software\MIS AG\PLAIN\"
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 43 5f 50 4c 41 49 4e 5f 56 42 41 57 4b 42 20 3d 20 22 41 58 4c 43 2e 58 4c 41 22 } //1 Public Const C_PLAIN_VBAWKB = "AXLC.XLA"
		$a_00_2 = {4f 6e 41 63 74 69 6f 6e 20 3d 20 22 4d 69 73 2e 50 6c 61 69 6e 2e 41 63 74 69 6f 6e 73 44 72 69 6c 6c 54 68 72 6f 75 67 68 2e 78 6c 61 21 45 76 61 6c 50 6f 70 55 70 41 63 74 69 6f 6e 73 22 } //1 OnAction = "Mis.Plain.ActionsDrillThrough.xla!EvalPopUpActions"
		$a_00_3 = {49 66 20 54 72 69 6d 28 73 4d 44 58 29 20 3d 20 22 22 20 54 68 65 6e 20 73 4d 44 58 20 3d 20 42 75 69 6c 64 44 72 69 6c 6c 54 68 72 6f 75 67 68 4d 44 58 } //1 If Trim(sMDX) = "" Then sMDX = BuildDrillThroughMDX
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_161{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {66 69 6c 65 50 61 74 68 20 3d 20 52 61 6e 67 65 28 22 43 33 22 29 2e 56 61 6c 75 65 20 26 20 22 5c 69 6b 6f 75 74 6f 64 6f 6b 65 5f 22 20 26 20 6e 65 6e 64 6f 20 26 20 22 2e 78 6c 73 78 22 } //1 filePath = Range("C3").Value & "\ikoutodoke_" & nendo & ".xlsx"
		$a_00_1 = {66 69 6c 65 50 61 74 68 32 20 3d 20 77 73 2e 43 65 6c 6c 73 28 34 2c 20 32 29 2e 56 61 6c 75 65 20 26 20 22 5c 62 61 63 6b 75 70 5c 69 6b 6f 75 74 6f 64 6f 6b 65 5f 22 20 26 20 6e 65 6e 64 6f 28 69 29 20 26 20 22 5f 62 61 6b 2e 78 6c 73 78 22 } //1 filePath2 = ws.Cells(4, 2).Value & "\backup\ikoutodoke_" & nendo(i) & "_bak.xlsx"
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 67 65 74 5f 6e 65 6e 64 6f 28 79 6d 64 29 } //1 Function get_nendo(ymd)
		$a_00_3 = {44 69 6d 20 6b 77 31 2c 20 6b 77 32 2c 20 6b 77 33 2c 20 64 66 2c 20 64 65 20 41 73 20 53 74 72 69 6e 67 } //1 Dim kw1, kw2, kw3, df, de As String
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_162{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 77 73 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 52 6f 73 74 65 72 22 29 } //2 Set ws = ThisWorkbook.Sheets("Roster")
		$a_00_1 = {73 43 6f 6d 70 61 72 65 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 52 6f 73 74 65 72 22 29 2e 52 61 6e 67 65 28 63 53 74 61 72 74 20 26 20 72 44 61 74 65 72 6f 77 29 2e 56 61 6c 75 65 } //2 sCompare = ThisWorkbook.Sheets("Roster").Range(cStart & rDaterow).Value
		$a_00_2 = {4d 65 2e 74 78 74 53 74 61 72 74 2e 56 61 6c 75 65 20 3d 20 46 6f 72 6d 61 74 28 66 72 6d 5f 44 61 74 65 53 65 6c 65 63 74 2e 54 61 67 2c 20 22 64 64 2d 6d 6d 6d 2d 79 79 79 79 22 29 } //2 Me.txtStart.Value = Format(frm_DateSelect.Tag, "dd-mmm-yyyy")
		$a_00_3 = {4d 73 67 42 6f 78 20 28 22 53 68 69 66 74 20 68 61 73 20 62 65 65 6e 20 73 61 76 65 64 2e 22 29 } //2 MsgBox ("Shift has been saved.")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_163{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 61 61 61 52 75 74 69 6e 65 73 5a 49 50 22 } //2 Attribute VB_Name = "aaaRutinesZIP"
		$a_00_1 = {44 69 6d 20 46 69 74 5a 69 70 20 41 73 20 56 61 72 69 61 6e 74 } //2 Dim FitZip As Variant
		$a_00_2 = {46 69 74 5a 69 70 20 3d 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 5a 69 70 4f 72 69 22 29 } //2 FitZip = CelDeNomBase("ZipOri")
		$a_00_3 = {44 65 73 63 6f 6d 70 72 69 6d 69 72 5a 49 50 20 46 69 74 5a 69 70 2c 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 44 69 72 44 65 73 22 29 20 27 20 22 63 3a 5c 74 73 74 5c 61 2e 7a 69 70 22 } //2 DescomprimirZIP FitZip, CelDeNomBase("DirDes") ' "c:\tst\a.zip"
		$a_00_4 = {4d 73 67 42 6f 78 20 4e 6f 6d 5a 49 50 6e 45 73 73 69 6d 28 46 69 74 5a 69 70 2c 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 6e 75 6d 22 29 29 } //2 MsgBox NomZIPnEssim(FitZip, CelDeNomBase("num"))
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=10
 
}
rule _#ASRWin32ApiMacroExclusion_164{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 0e 00 00 "
		
	strings :
		$a_00_0 = {73 6f 6c 76 65 72 33 32 2e 64 6c 6c } //3 solver32.dll
		$a_00_1 = {73 6f 6c 76 65 72 6f 6b } //1 solverok
		$a_00_2 = {73 6f 6c 76 65 72 6f 6b 64 69 61 6c 6f 67 } //1 solverokdialog
		$a_00_3 = {73 6f 6c 76 65 72 63 6f 64 65 } //1 solvercode
		$a_00_4 = {73 6f 6c 76 65 72 63 61 6c 6c 73 } //1 solvercalls
		$a_00_5 = {73 6f 6c 76 65 72 73 6f 6c 76 65 } //1 solversolve
		$a_00_6 = {73 6f 6c 76 65 72 61 64 64 } //1 solveradd
		$a_00_7 = {73 6f 6c 76 65 72 63 68 61 6e 67 65 } //1 solverchange
		$a_00_8 = {73 6f 6c 76 65 72 64 65 6c 65 74 65 } //1 solverdelete
		$a_00_9 = {73 6f 6c 76 65 72 66 69 6e 69 73 68 } //1 solverfinish
		$a_00_10 = {73 6f 6c 76 65 72 67 65 74 } //1 solverget
		$a_00_11 = {73 6f 6c 76 65 72 6f 70 74 69 6f 6e 73 } //1 solveroptions
		$a_00_12 = {73 6f 6c 76 65 72 72 65 73 65 74 } //1 solverreset
		$a_00_13 = {64 6c 67 73 6f 6c 76 65 72 70 61 72 61 6d 65 74 65 72 73 } //1 dlgsolverparameters
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1) >=9
 
}
rule _#ASRWin32ApiMacroExclusion_165{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 55 42 4b 45 59 20 3d 20 22 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 54 47 44 6f 63 58 2e 65 78 65 22 } //2 Public Const SUBKEY = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ITGDocX.exe"
		$a_00_1 = {56 69 73 69 6f 2e 41 64 64 6f 6e 73 2e 49 74 65 6d 28 73 74 72 41 70 70 50 61 74 68 20 26 20 22 49 54 47 44 6f 63 58 2e 65 78 65 22 29 2e 52 75 6e 20 28 22 53 70 6c 61 73 68 22 29 } //2 Visio.Addons.Item(strAppPath & "ITGDocX.exe").Run ("Splash")
		$a_00_2 = {43 68 6f 69 63 65 20 3d 20 4d 73 67 42 6f 78 28 73 74 72 4d 73 67 2c 20 76 62 59 65 73 4e 6f 20 2b 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e 2c 20 22 49 54 47 20 44 65 73 69 67 6e 22 } //2 Choice = MsgBox(strMsg, vbYesNo + vbExclamation, "ITG Design"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_166{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 41 70 69 50 72 65 66 69 78 50 6d 74 50 72 6f 64 73 20 3d 20 22 68 74 74 70 73 3a 2f 2f 73 70 32 30 31 33 2e 6d 79 61 74 6f 73 2e 6e 65 74 2f 6f 72 67 61 6e 69 7a 61 74 69 6f 6e 2f 67 62 75 2f 77 6c 2f 65 77 6c 2f 63 6f 6f 2f 50 61 79 6d 65 6e 74 73 25 32 30 70 72 6f 64 75 63 74 73 2f 5f 61 70 69 22 } //2 Const ApiPrefixPmtProds = "https://sp2013.myatos.net/organization/gbu/wl/ewl/coo/Payments%20products/_api"
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 61 63 63 2d 6a 69 72 61 2e 77 6f 72 6c 64 6c 69 6e 65 2e 63 6f 6d } //2 https://acc-jira.worldline.com
		$a_00_2 = {68 74 74 70 73 3a 2f 2f 63 68 61 6c 6c 65 6e 67 65 2e 70 61 79 31 2d 74 65 73 74 2e 64 65 2f 63 61 6c 63 75 6c 6f 6e 3f 72 73 6c 74 3d } //2 https://challenge.pay1-test.de/calculon?rslt=
		$a_00_3 = {69 73 73 75 65 4b 65 79 20 3d 20 22 45 32 45 43 44 2d 32 38 32 39 22 } //2 issueKey = "E2ECD-2829"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_167{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 45 78 70 6f 72 74 44 61 74 61 4f 62 6a 65 63 74 54 6f 58 4d 4c 28 63 6f 6c 52 69 73 6b 44 61 74 61 20 41 73 20 63 6c 73 52 69 73 6b 44 61 74 61 43 6f 6c 2c 20 6d 66 46 69 6c 74 65 72 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub ExportDataObjectToXML(colRiskData As clsRiskDataCol, mfFilter As String)
		$a_00_1 = {2e 49 64 20 3d 20 4c 43 61 73 65 28 72 69 73 6b 44 61 74 61 2e 4d 61 69 6e 46 75 6e 63 74 69 6f 6e 49 44 20 26 20 22 3b 22 20 26 20 72 69 73 6b 44 61 74 61 2e 53 75 62 46 75 6e 63 74 69 6f 6e 20 26 20 22 3b 22 20 26 20 63 75 72 72 52 6f 77 29 } //1 .Id = LCase(riskData.MainFunctionID & ";" & riskData.SubFunction & ";" & currRow)
		$a_00_2 = {63 6f 6c 52 69 73 6b 44 61 74 61 2e 52 65 73 6f 6c 76 65 52 69 73 6b 20 63 6f 6c 52 69 73 6b 44 61 74 61 2e 49 74 65 6d 73 2e 69 74 65 6d 28 69 50 6f 73 29 } //1 colRiskData.ResolveRisk colRiskData.Items.item(iPos)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_168{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 4d 6f 64 46 69 6c 65 54 6f 6f 6c 5f 53 65 74 46 6f 72 6d 61 74 28 52 47 20 41 73 20 52 61 6e 67 65 2c 20 46 47 20 41 73 20 49 6e 74 65 67 65 72 29 } //1 Public Sub ModFileTool_SetFormat(RG As Range, FG As Integer)
		$a_00_1 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 63 6b 5f 46 49 4c 45 4e 41 4d 45 5f 58 4c 53 5f 4a 28 52 47 20 41 73 20 52 61 6e 67 65 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //1 Private Function ck_FILENAME_XLS_J(RG As Range) As Boolean
		$a_00_2 = {49 66 20 63 6f 5f 43 4b 44 41 54 41 4e 41 4d 45 20 3d 20 22 46 45 48 5f 53 54 41 54 44 42 49 4e 46 22 20 54 68 65 6e } //1 If co_CKDATANAME = "FEH_STATDBINF" Then
		$a_00_3 = {43 61 6c 6c 20 61 64 64 44 61 74 61 43 6b 43 6f 6c 28 43 65 6c 6c 73 28 6d 79 6c 69 6e 65 2c 20 63 6f 5f 44 61 74 61 5f 43 4b 5f 63 6f 6c 29 29 } //1 Call addDataCkCol(Cells(myline, co_Data_CK_col))
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_169{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {73 6f 66 74 77 61 72 65 5c 64 61 74 61 73 74 72 65 61 6d 5c 64 61 74 61 73 74 72 65 61 6d 20 61 64 76 61 6e 63 65 5c 70 65 72 73 69 73 74 65 6e 63 65 5c 70 6f 77 65 72 73 65 61 72 63 68 } //2 software\datastream\datastream advance\persistence\powersearch
		$a_00_1 = {73 6f 66 74 77 61 72 65 5c 64 61 74 61 73 74 72 65 61 6d 5c 64 61 74 61 73 74 72 65 61 6d 20 61 64 76 61 6e 63 65 5c 6d 69 73 63 } //2 software\datastream\datastream advance\misc
		$a_00_2 = {73 6f 66 74 77 61 72 65 5c 64 61 74 61 73 74 72 65 61 6d 5c 64 61 74 61 73 74 72 65 61 6d 20 61 64 76 61 6e 63 65 5c 66 69 6c 65 73 } //2 software\datastream\datastream advance\files
		$a_00_3 = {68 74 74 70 3a 2f 2f 70 72 6f 64 75 63 74 2e 64 61 74 61 73 74 72 65 61 6d 2e 63 6f 6d 2f 75 63 69 2f } //2 http://product.datastream.com/uci/
		$a_00_4 = {61 64 76 61 6e 63 65 20 66 6f 72 20 6f 66 66 69 63 65 } //2 advance for office
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_170{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 41 76 61 79 61 20 49 6e 64 69 61 20 4c 69 6d 69 74 65 64 22 } //2 ActiveSheet.Cells(lastrow, 1).Value = "Avaya India Limited"
		$a_00_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 52 53 41 32 20 53 65 63 75 72 69 74 79 20 26 20 52 69 73 6b 20 49 72 65 6c 61 6e 64 20 4c 69 6d 69 74 65 64 22 } //2 ActiveSheet.Cells(lastrow, 1).Value = "RSA2 Security & Risk Ireland Limited"
		$a_00_2 = {41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 50 75 72 65 20 53 74 6f 72 61 67 65 20 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 20 4c 69 6d 69 74 65 64 22 } //2 ActiveSheet.Cells(lastrow, 1).Value = "Pure Storage International Limited"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_171{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 22 4d 41 53 5b 5b 43 65 6e 74 72 61 6c 20 2f 20 4c 6f 63 61 6c 20 43 6f 6c 6c 65 63 74 69 6f 6e 5d 3a 5b 43 6f 6c 6c 65 63 74 69 6f 6e 20 4c 6f 63 61 74 69 6f 6e 5d 5d 22 29 } //2 Range("MAS[[Central / Local Collection]:[Collection Location]]")
		$a_00_1 = {52 61 6e 67 65 28 22 4d 41 53 5b 5b 4c 6f 63 61 6c 20 49 6e 73 75 72 65 72 5d 3a 5b 49 6e 74 72 61 63 6f 6d 70 61 6e 79 20 50 6f 6c 69 63 79 20 2f 20 52 65 69 6e 73 75 72 61 6e 63 65 20 41 67 72 65 65 6d 65 6e 74 20 4e 75 6d 62 65 72 5d 5d 22 29 } //2 Range("MAS[[Local Insurer]:[Intracompany Policy / Reinsurance Agreement Number]]")
		$a_00_2 = {52 61 6e 67 65 28 22 4d 41 53 5b 5b 4c 6f 63 61 6c 20 50 6f 6c 69 63 79 20 43 75 72 72 65 6e 63 79 5d 3a 5b 4c 6f 63 61 6c 20 50 6f 6c 69 63 79 20 43 75 72 72 65 6e 63 79 20 52 4f 45 5d 5d 22 29 } //2 Range("MAS[[Local Policy Currency]:[Local Policy Currency ROE]]")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_172{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 77 6f 72 6b 69 6e 67 46 6f 6c 64 65 72 20 3d 20 22 43 3a 5c 55 74 69 6c 5c 66 72 65 65 6a 65 74 5c 22 } //1 Private Const workingFolder = "C:\Util\freejet\"
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 66 72 65 65 4a 65 74 46 6f 6c 64 65 72 20 3d 20 22 46 72 65 65 4a 65 74 5c 72 65 73 6f 75 72 63 65 73 5c 22 } //1 Private Const freeJetFolder = "FreeJet\resources\"
		$a_00_2 = {65 78 65 63 75 74 61 62 6c 65 73 5f 6c 6f 63 61 74 69 6f 6e 20 3d 20 73 74 72 44 6f 63 75 6d 65 6e 74 73 20 26 20 22 5c 22 20 26 20 66 72 65 65 4a 65 74 46 6f 6c 64 65 72 } //1 executables_location = strDocuments & "\" & freeJetFolder
		$a_00_3 = {66 69 6c 65 50 61 74 68 20 3d 20 77 6f 72 6b 69 6e 67 46 6f 6c 64 65 72 20 26 20 62 70 32 64 69 6d 46 69 6c 65 4e 61 6d 65 20 26 20 22 2e 46 53 54 45 49 4e 22 } //1 filePath = workingFolder & bp2dimFileName & ".FSTEIN"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_173{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 33 29 20 3d 20 62 75 69 6c 64 50 68 61 73 65 43 6f 6d 62 6f 2e 54 65 78 74 } //1 Range(3) = buildPhaseCombo.Text
		$a_00_1 = {64 65 76 69 63 65 2e 41 64 64 20 22 73 73 64 56 65 6e 64 6f 72 22 2c 20 2e 52 61 6e 67 65 28 63 6f 6c 75 6d 6e 4d 61 70 28 22 53 53 44 20 56 65 6e 64 6f 72 22 29 29 } //1 device.Add "ssdVendor", .Range(columnMap("SSD Vendor"))
		$a_00_2 = {64 65 76 69 63 65 2e 41 64 64 20 22 73 6b 75 22 2c 20 2e 52 61 6e 67 65 28 63 6f 6c 75 6d 6e 4d 61 70 28 22 53 4b 55 22 29 29 } //1 device.Add "sku", .Range(columnMap("SKU"))
		$a_00_3 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 72 6f 77 54 6f 44 69 63 74 28 72 6f 77 20 41 73 20 4c 69 73 74 52 6f 77 2c 20 63 6f 6c 75 6d 6e 4d 61 70 20 41 73 20 44 69 63 74 69 6f 6e 61 72 79 29 20 41 73 20 44 69 63 74 69 6f 6e 61 72 79 } //1 Private Function rowToDict(row As ListRow, columnMap As Dictionary) As Dictionary
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_174{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 4d 75 6e 69 42 6c 6f 6f 6d 62 65 72 67 28 63 75 73 69 70 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub MuniBloomberg(cusip As String)
		$a_00_1 = {53 65 74 20 72 57 69 6e 64 6f 77 73 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 28 61 64 64 69 6e 5f 6e 61 6d 65 29 2e 53 68 65 65 74 73 28 22 56 61 6c 75 65 73 22 29 2e 52 61 6e 67 65 28 22 42 6c 6f 6f 6d 62 65 72 67 57 69 6e 64 6f 77 73 22 29 } //1 Set rWindows = Workbooks(addin_name).Sheets("Values").Range("BloombergWindows")
		$a_00_2 = {53 75 62 20 4d 75 6e 69 42 6c 6f 6f 6d 62 65 72 67 53 65 6e 64 42 6f 6e 64 28 63 75 73 69 70 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub MuniBloombergSendBond(cusip As String)
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 4d 75 6e 69 42 6c 6f 6f 6d 62 65 72 67 54 43 28 6d 61 73 74 65 72 54 69 63 6b 65 74 4e 75 6d 62 65 72 20 41 73 20 53 74 72 69 6e 67 29 } //1 Public Sub MuniBloombergTC(masterTicketNumber As String)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_175{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 62 62 2e 43 61 70 74 69 6f 6e 20 3d 20 22 46 61 7a 53 70 69 65 67 65 6c 2d 4c 6f 67 } //1 cbb.Caption = "FazSpiegel-Log
		$a_00_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 57 6f 72 6b 73 68 65 65 74 20 4d 65 6e 75 20 42 61 72 22 29 2e 43 6f 6e 74 72 6f 6c 73 28 22 45 78 74 72 61 73 22 29 2e 43 6f 6e 74 72 6f 6c 73 28 22 46 41 5a 20 53 70 69 65 67 65 6c 22 29 2e 44 65 6c 65 74 65 } //1 Application.CommandBars("Worksheet Menu Bar").Controls("Extras").Controls("FAZ Spiegel").Delete
		$a_00_2 = {53 74 72 69 6e 67 32 46 69 6c 65 20 46 61 7a 43 6f 6e 66 69 67 46 69 6c 65 2c 20 74 78 74 49 6e 69 66 69 6c 65 2e 54 65 78 74 2c 20 46 61 6c 73 65 } //1 String2File FazConfigFile, txtInifile.Text, False
		$a_00_3 = {46 61 7a 53 70 69 65 67 65 6c 41 75 73 67 61 62 65 20 3d 20 63 41 75 73 67 61 62 65 53 74 65 6c 6c 65 6e 6d 61 72 6b 74 } //1 FazSpiegelAusgabe = cAusgabeStellenmarkt
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_176{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4b 72 6f 6e 65 73 44 61 74 61 49 6e 74 65 72 66 61 63 65 5f 4b 34 34 33 33 39 30 5f 42 6c 6f 77 2d 4d 6f 75 6c 64 65 72 5f 43 6f 6d 6d 69 73 73 69 6f 6e 69 6e 67 2e 78 6c 73 } //1 KronesDataInterface_K443390_Blow-Moulder_Commissioning.xls
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 6d 6f 64 75 6c 6e 61 6d 65 20 3d 20 22 55 46 5f 43 68 65 63 6b 4b 6f 6d 4e 6f 4d 61 6e 75 61 6c 22 } //1 Private Const modulname = "UF_CheckKomNoManual"
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 54 78 74 5f 4b 6f 6d 4e 6f 5f 41 66 74 65 72 55 70 64 61 74 65 28 29 } //1 Private Sub Txt_KomNo_AfterUpdate()
		$a_00_3 = {43 61 6c 6c 20 46 6f 72 6d 61 74 53 68 65 65 74 45 6e 74 72 69 65 73 28 73 68 74 2c 20 72 6e 67 53 2e 52 61 6e 67 65 2c 20 22 46 54 5f 57 68 69 74 65 53 74 61 6e 64 61 72 73 22 2c 20 46 61 6c 73 65 2c 20 54 72 75 65 29 } //1 Call FormatSheetEntries(sht, rngS.Range, "FT_WhiteStandars", False, True)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_177{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 62 6f 6f 6b 20 3d 20 77 62 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 41 64 64 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 73 70 69 6e 6e 65 72 2e 78 6c 73 6d 22 29 } //1 Set book = wb.Workbooks.Add(ThisWorkbook.Path & "\spinner.xlsm")
		$a_00_1 = {4f 70 65 6e 20 73 65 63 6f 6e 64 61 72 79 20 73 68 65 65 74 20 74 6f 20 73 68 6f 77 20 73 70 69 6e 6e 65 72 } //1 Open secondary sheet to show spinner
		$a_00_2 = {53 65 74 20 6f 52 6e 67 20 3d 20 49 6e 74 65 72 73 65 63 74 28 53 65 6c 65 63 74 69 6f 6e 2c 20 53 65 6c 65 63 74 69 6f 6e 2e 50 61 72 65 6e 74 2e 55 73 65 64 52 61 6e 67 65 } //1 Set oRng = Intersect(Selection, Selection.Parent.UsedRange
		$a_00_3 = {49 66 20 63 79 46 72 65 71 75 65 6e 63 79 20 54 68 65 6e 20 4d 69 63 72 6f 54 69 6d 65 72 20 3d 20 63 79 54 69 63 6b 73 31 20 2f 20 63 79 46 72 65 71 75 65 6e 63 79 } //1 If cyFrequency Then MicroTimer = cyTicks1 / cyFrequency
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_178{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {44 61 74 61 2e 54 61 62 6c 65 4e 61 6d 65 20 3d 20 22 41 67 49 6e 70 75 74 44 61 74 61 22 } //1 Data.TableName = "AgInputData"
		$a_00_1 = {66 69 65 6c 64 73 2e 41 70 70 65 6e 64 20 22 4c 69 76 65 73 74 6f 63 6b 50 72 6f 64 75 63 74 73 41 63 63 72 75 61 6c 41 64 6a 75 73 74 6d 65 6e 74 22 } //1 fields.Append "LivestockProductsAccrualAdjustment"
		$a_00_2 = {66 69 65 6c 64 73 2e 41 70 70 65 6e 64 20 22 43 72 6f 70 49 6e 73 75 72 61 6e 63 65 41 6e 64 44 69 73 61 73 74 65 72 50 72 6f 63 65 65 64 73 22 } //1 fields.Append "CropInsuranceAndDisasterProceeds"
		$a_00_3 = {49 6e 76 65 73 74 6d 65 6e 74 49 6e 47 72 6f 77 69 6e 67 43 72 6f 70 73 41 63 63 72 75 61 6c 41 64 6a 75 73 74 6d 65 6e 74 } //1 InvestmentInGrowingCropsAccrualAdjustment
		$a_00_4 = {41 63 63 75 6d 75 6c 61 74 65 64 44 65 70 72 65 63 69 61 74 69 6f 6e 4d 61 63 68 69 6e 65 72 79 45 71 75 69 70 6d 65 6e 74 } //1 AccumulatedDepreciationMachineryEquipment
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_179{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 54 79 70 65 20 74 4d 69 6c 65 73 74 6f 6e 65 } //5 Public Type tMilestone
		$a_01_1 = {50 75 62 6c 69 63 20 53 75 62 20 75 70 64 61 74 65 5f 54 69 6d 65 6c 69 6e 65 28 73 74 61 72 74 44 61 74 65 2c 20 6e 65 77 54 6c 50 65 72 69 6f 64 2c 20 74 6c 57 65 65 6b 73 20 41 73 20 42 6f 6f 6c 65 61 6e 2c 20 6e 65 77 50 6f 6f 6c 43 6f 6c 73 29 } //2 Public Sub update_Timeline(startDate, newTlPeriod, tlWeeks As Boolean, newPoolCols)
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 52 44 50 5f 50 52 4e 73 28 29 20 41 73 20 56 61 72 69 61 6e 74 } //1 Function RDP_PRNs() As Variant
		$a_01_3 = {46 75 6e 63 74 69 6f 6e 20 61 62 62 72 65 76 69 61 74 65 5f 4d 53 5f 4e 61 6d 65 28 6d 73 4e 61 6d 65 29 } //1 Function abbreviate_MS_Name(msName)
		$a_01_4 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 74 72 69 6d 54 69 6d 65 28 64 61 74 65 5f 77 69 74 68 5f 74 69 6d 65 29 } //1 Public Function trimTime(date_with_time)
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}
rule _#ASRWin32ApiMacroExclusion_180{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 6d 64 41 64 64 5f 45 64 69 74 5f 56 69 65 77 22 } //2 Attribute VB_Name = "mdAdd_Edit_View"
		$a_00_1 = {53 65 74 20 77 4d 61 72 6b 20 3d 20 61 75 64 69 74 65 64 53 68 65 65 74 2e 53 68 61 70 65 73 28 22 44 72 61 66 74 57 61 74 65 72 6d 61 72 6b 22 29 } //2 Set wMark = auditedSheet.Shapes("DraftWatermark")
		$a_00_2 = {47 65 74 53 65 72 76 65 72 54 69 6d 65 20 3d 20 67 65 74 52 65 6d 6f 74 65 54 4f 44 28 22 5c 5c 6e 69 2d 63 72 2d 73 76 63 2d 64 63 31 22 29 } //2 GetServerTime = getRemoteTOD("\\ni-cr-svc-dc1")
		$a_00_3 = {53 65 74 20 64 61 74 61 46 69 65 6c 64 43 6f 6c 73 20 3d 20 6e 65 77 41 75 64 69 74 53 68 74 2e 43 6f 6c 75 6d 6e 73 28 63 6f 6c 50 61 72 61 6d 31 29 2e 52 65 73 69 7a 65 28 43 6f 6c 75 6d 6e 53 69 7a 65 3a 3d 6e 75 6d 43 6f 6c 73 20 2a 20 32 29 } //2 Set dataFieldCols = newAuditSht.Columns(colParam1).Resize(ColumnSize:=numCols * 2)
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_181{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 50 4d 53 58 44 61 74 61 46 69 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 46 4f 44 4d 63 6f 6d 6d 4d 53 58 44 61 74 61 2e 78 6c 73 78 22 } //2 Public Const SPMSXDataFileName As String = "FODMcommMSXData.xlsx"
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 74 6f 6f 6c 54 69 74 6c 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 53 70 6f 74 6c 69 67 68 74 20 2d 20 47 46 4f 20 41 75 74 6f 6d 61 74 65 64 20 43 6f 6d 6d 20 54 6f 6f 6c 22 } //2 Public Const toolTitle As String = "Spotlight - GFO Automated Comm Tool"
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 4c 49 52 53 65 72 76 65 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 6d 62 6f 64 65 73 79 6e 61 70 73 65 2d 6f 6e 64 65 6d 61 6e 64 2e 53 71 6c 2e 61 7a 75 72 65 73 79 6e 61 70 73 65 2e 6e 65 74 22 } //2 Public Const LIRServerName As String = "mbodesynapse-ondemand.Sql.azuresynapse.net"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_182{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 20 4e 61 6d 65 3a 20 20 56 6f 79 61 67 65 72 50 6c 61 6e 20 44 69 61 67 72 61 6d 20 50 72 69 6e 74 20 4d 61 63 72 6f 73 } //1 Application  Name:  VoyagerPlan Diagram Print Macros
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 50 75 62 4d 61 63 72 6f 73 22 } //1 Attribute VB_Name = "PubMacros"
		$a_00_2 = {55 4b 3a 31 32 30 31 34 39 39 31 20 2d 20 52 65 6d 6f 76 65 64 20 53 61 76 65 44 6f 63 75 6d 65 6e 74 20 63 61 6c 6c 20 61 73 20 69 74 20 77 69 6c 6c 20 62 65 20 73 61 76 65 64 20 66 72 6f 6d 20 56 50 52 49 31 33 35 30 2e 64 6c 6c } //1 UK:12014991 - Removed SaveDocument call as it will be saved from VPRI1350.dll
		$a_00_3 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 6d 63 4d 6f 64 75 6c 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 44 69 61 67 72 61 6d 20 50 72 69 6e 74 20 4d 61 63 72 6f 73 22 } //1 Private Const mcModule As String = "Diagram Print Macros"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_183{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 73 6f 72 74 42 52 42 53 68 65 65 74 28 73 68 65 65 74 53 65 6c 65 63 74 65 64 20 41 73 20 57 6f 72 6b 73 68 65 65 74 2c 20 63 65 6c 6c 53 65 6c 65 63 74 65 64 20 41 73 20 52 61 6e 67 65 2c 20 73 6f 72 74 44 69 72 65 63 74 69 6f 6e 20 41 73 20 58 6c 53 6f 72 74 4f 72 64 65 72 29 } //2 Public Sub sortBRBSheet(sheetSelected As Worksheet, cellSelected As Range, sortDirection As XlSortOrder)
		$a_00_1 = {49 66 20 73 68 65 65 74 53 65 6c 65 63 74 65 64 2e 6e 61 6d 65 20 3d 20 22 57 6f 57 20 44 69 67 65 73 74 22 20 54 68 65 6e } //2 If sheetSelected.name = "WoW Digest" Then
		$a_00_2 = {53 65 74 20 63 6f 6c 75 6d 6e 73 42 79 48 65 61 64 65 72 20 3d 20 57 6f 72 6b 62 65 6e 63 68 55 46 2e 61 6e 6e 6f 74 61 74 69 6f 6e 73 41 70 70 2e 72 65 76 65 6e 75 65 52 65 70 6f 72 74 43 6f 6c 75 6d 6e 73 42 79 48 65 61 64 65 72 } //2 Set columnsByHeader = WorkbenchUF.annotationsApp.revenueReportColumnsByHeader
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_184{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 53 45 52 56 4c 45 54 5f 50 41 54 48 20 3d 20 22 68 74 74 70 3a 2f 2f 63 72 2d 73 76 63 2d 66 69 6e 31 2e 70 68 61 72 6d 73 2d 73 65 72 76 69 63 65 73 2e 63 6f 6d 3a 38 30 30 30 2f 6f 61 5f 73 65 72 76 6c 65 74 73 2f 22 } //1 Const SERVLET_PATH = "http://cr-svc-fin1.pharms-services.com:8000/oa_servlets/"
		$a_00_1 = {47 65 6e 65 72 61 74 65 64 3a 42 6e 65 4f 41 45 78 63 65 6c } //1 Generated:BneOAExcel
		$a_00_2 = {41 64 64 42 6e 65 4d 73 67 20 42 4e 45 5f 45 52 52 4f 52 2c 20 22 42 6e 65 55 70 6c 6f 61 64 42 65 67 69 6e 22 2c 20 22 43 6f 75 6c 64 6e 27 74 20 43 72 65 61 74 65 20 61 20 44 4f 4d 20 44 6f 63 75 6d 65 6e 74 22 } //1 AddBneMsg BNE_ERROR, "BneUploadBegin", "Couldn't Create a DOM Document"
		$a_00_3 = {43 6f 6e 73 74 20 44 45 42 55 47 5f 44 4f 43 55 4d 45 4e 54 20 3d 20 22 63 3a 5c 42 6e 65 44 65 62 75 67 2d 44 6f 63 75 6d 65 6e 74 2e 78 6d 6c 22 } //1 Const DEBUG_DOCUMENT = "c:\BneDebug-Document.xml"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_185{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4f 75 74 70 75 74 54 78 74 20 3d 20 22 43 6f 6e 74 72 61 63 74 2c 20 44 61 74 65 2c 20 50 44 2c 20 4c 47 44 2c 20 64 4c 47 44 2e 22 } //1 OutputTxt = "Contract, Date, PD, LGD, dLGD."
		$a_00_1 = {53 68 65 65 74 73 28 22 53 41 50 20 75 70 20 56 53 20 43 53 56 22 29 2e 43 65 6c 6c 73 28 32 2c 20 32 30 29 2e 56 61 6c 75 65 20 3d 20 43 4f 6e 64 69 } //1 Sheets("SAP up VS CSV").Cells(2, 20).Value = COndi
		$a_00_2 = {66 75 6e 63 74 69 6f 6e 73 2e 43 6f 6e 6e 65 63 74 69 6f 6e 2e 41 70 70 6c 69 63 61 74 69 6f 6e 53 65 72 76 65 72 20 3d 20 22 70 72 65 6d 73 61 70 2e 69 74 2e 6e 65 64 6e 65 74 2e 63 6f 2e 7a 61 22 } //1 functions.Connection.ApplicationServer = "premsap.it.nednet.co.za"
		$a_00_3 = {53 65 74 20 52 66 63 43 61 6c 6c 54 72 61 6e 73 61 63 74 69 6f 6e 20 3d 20 66 75 6e 63 74 69 6f 6e 73 2e 41 64 64 28 22 42 42 50 5f 52 46 43 5f 52 45 41 44 5f 54 41 42 4c 45 22 29 } //1 Set RfcCallTransaction = functions.Add("BBP_RFC_READ_TABLE")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_186{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {49 66 20 6d 75 2e 43 61 70 74 69 6f 6e 20 3d 20 22 26 41 73 70 65 6e 20 50 72 6f 70 65 72 74 69 65 73 22 20 54 68 65 6e } //1 If mu.Caption = "&Aspen Properties" Then
		$a_00_1 = {50 75 62 6c 69 63 20 67 5f 41 73 70 65 6e 50 72 6f 70 65 72 74 69 65 73 53 74 61 72 74 75 70 64 69 72 20 41 73 20 53 74 72 69 6e 67 } //1 Public g_AspenPropertiesStartupdir As String
		$a_00_2 = {73 74 72 50 61 74 68 2c 20 70 73 7a 54 69 74 6c 65 3a 3d 22 53 65 6c 65 63 74 20 41 73 70 65 6e 20 50 72 6f 70 65 72 74 69 65 73 20 77 6f 72 6b 69 6e 67 20 66 6f 6c 64 65 72 3a 22 29 } //1 strPath, pszTitle:="Select Aspen Properties working folder:")
		$a_00_3 = {53 65 74 20 6d 6f 62 6a 48 61 70 70 48 61 70 70 49 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 73 70 65 6e 50 72 6f 70 65 72 74 69 65 73 2e 44 6f 63 75 6d 65 6e 74 2e 22 20 2b 20 67 5f 4d 4d 56 65 72 73 69 6f 6e 29 } //1 Set mobjHappHappIp = CreateObject("AspenProperties.Document." + g_MMVersion)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_187{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {2e 4f 70 65 6e 20 22 50 4f 53 54 22 2c 20 22 68 74 74 70 3a 2f 2f 76 69 73 61 73 63 72 73 2e 66 63 6f 2e 67 73 69 2e 67 6f 76 2e 75 6b 2f 55 4b 43 52 53 2f 55 4b 43 52 53 4d 65 6e 75 2f 4d 45 4e 55 5f 6c 6f 67 69 6e 2e 61 73 70 22 } //2 .Open "POST", "http://visascrs.fco.gsi.gov.uk/UKCRS/UKCRSMenu/MENU_login.asp"
		$a_00_1 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 46 6f 6c 6c 6f 77 48 79 70 65 72 6c 69 6e 6b 20 50 4f 49 53 45 5f 6f 72 5f 54 53 5f 4c 69 6e 6b 20 26 20 22 5c 64 61 74 61 20 61 6e 61 6c 79 73 69 73 20 74 65 61 6d 5c 4e 65 77 20 44 41 20 54 65 61 6d 20 53 74 72 75 63 74 75 72 65 5c 57 52 20 57 6f 72 6b 20 52 65 71 75 65 73 74 73 5c 52 65 67 75 6c 61 72 5c 57 52 31 38 36 39 } //2 ThisWorkbook.FollowHyperlink POISE_or_TS_Link & "\data analysis team\New DA Team Structure\WR Work Requests\Regular\WR1869
		$a_00_2 = {6f 62 6a 4f 4c 2e 47 65 74 4e 61 6d 65 73 70 61 63 65 28 22 4d 41 50 49 22 29 } //2 objOL.GetNamespace("MAPI")
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_188{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 41 4a 5f 63 65 6c 6c 75 6c 65 5f 69 6d 70 6f 72 74 20 53 68 65 65 74 73 28 22 50 72 47 2c 20 54 2e 50 2e 2c 20 64 73 44 4e 41 22 29 } //1 MAJ_cellule_import Sheets("PrG, T.P., dsDNA")
		$a_00_1 = {70 61 74 68 5f 64 62 20 3d 20 22 5c 5c 4e 54 42 52 41 46 53 43 4c 30 31 31 5c 64 66 73 5c 53 69 74 65 73 5c 42 72 61 69 6e 65 5c 47 54 53 4f 5c 47 50 44 49 5c 43 43 50 44 5c 41 6e 61 6c 79 74 69 63 73 5c 44 42 20 50 51 41 5c 44 61 74 61 42 61 73 65 20 55 50 53 20 56 31 2e 30 5f 62 65 2e 61 63 63 64 62 22 } //1 path_db = "\\NTBRAFSCL011\dfs\Sites\Braine\GTSO\GPDI\CCPD\Analytics\DB PQA\DataBase UPS V1.0_be.accdb"
		$a_00_2 = {49 6e 48 6f 73 74 4e 61 6d 65 20 3d 20 22 47 44 43 53 4c 44 43 41 50 30 30 31 22 } //1 InHostName = "GDCSLDCAP001"
		$a_00_3 = {49 66 20 4d 79 5f 77 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 39 29 2e 52 61 6e 67 65 28 22 43 51 41 5f 67 72 61 70 68 5f 6c 69 73 74 22 29 } //1 If My_workbook.Sheets(9).Range("CQA_graph_list")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_189{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 46 69 6c 65 6e 61 6d 65 3a 3d 73 74 72 50 65 72 45 69 6e 73 74 20 26 20 22 45 49 4e 53 54 45 4c 4c 55 4e 47 45 4e 2e 78 6c 73 78 22 } //1 Workbooks.Open Filename:=strPerEinst & "EINSTELLUNGEN.xlsx"
		$a_00_1 = {73 74 72 53 51 4c 20 3d 20 22 53 45 4c 45 43 54 20 47 45 4d 45 49 4e 44 45 20 46 52 4f 4d 20 46 55 5f 4c 5f 47 45 4d 45 49 4e 44 45 5f 4f 52 54 53 54 45 49 4c 22 } //1 strSQL = "SELECT GEMEINDE FROM FU_L_GEMEINDE_ORTSTEIL"
		$a_00_2 = {73 74 72 44 41 54 45 49 4e 65 77 20 3d 20 44 41 54 55 4d 5f 44 41 54 45 49 20 26 20 22 42 41 43 4b 55 50 2e 4d 53 50 5f 54 6f 6f 6c 2e 78 6c 73 6d 22 } //1 strDATEINew = DATUM_DATEI & "BACKUP.MSP_Tool.xlsm"
		$a_00_3 = {73 74 72 44 41 54 45 49 4e 65 77 56 69 73 69 6f 6e 20 3d 20 44 41 54 55 4d 5f 44 41 54 45 49 20 26 20 22 6e 65 77 56 69 73 69 6f 6e 2e 4d 53 50 5f 54 6f 6f 6c 2e 78 6c 73 6d 22 } //1 strDATEINewVision = DATUM_DATEI & "newVision.MSP_Tool.xlsm"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_190{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 22 70 72 6f 63 65 73 73 69 6e 67 44 61 74 65 22 29 20 3d 20 53 75 62 6d 69 74 56 41 54 52 65 74 75 72 6e 41 50 49 2e 50 72 6f 63 65 73 73 69 6e 67 44 61 74 65 } //2 Range("processingDate") = SubmitVATReturnAPI.ProcessingDate
		$a_00_1 = {2e 52 61 6e 67 65 28 22 63 68 61 72 67 65 52 65 66 4e 75 6d 62 65 72 22 29 20 3d 20 22 27 22 20 26 20 53 75 62 6d 69 74 56 41 54 52 65 74 75 72 6e 41 50 49 2e 43 68 61 72 67 65 52 65 66 4e 75 6d 62 65 72 } //2 .Range("chargeRefNumber") = "'" & SubmitVATReturnAPI.ChargeRefNumber
		$a_00_2 = {45 72 72 2e 52 61 69 73 65 20 2e 73 74 61 74 75 73 2c 20 22 53 75 62 6d 69 74 56 41 54 52 65 74 75 72 6e 41 50 49 22 2c 20 22 54 68 65 20 56 41 54 20 72 65 74 75 72 6e 20 77 61 73 20 61 6c 72 65 61 64 79 20 73 75 62 6d 69 74 74 65 64 20 66 6f 72 20 74 68 65 20 67 69 76 65 6e 20 70 65 72 69 6f 64 2e 22 } //2 Err.Raise .status, "SubmitVATReturnAPI", "The VAT return was already submitted for the given period."
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_191{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 69 29 2e 43 65 6c 6c 73 28 31 2c 20 6c 61 73 74 63 6f 6c 20 2b 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 54 6f 74 61 6c 43 61 6c 63 75 6c 61 74 69 6f 6e 56 61 6c 75 65 } //2 ThisWorkbook.Worksheets(i).Cells(1, lastcol + 1).Value = "TotalCalculationValue
		$a_01_1 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 69 29 2e 43 65 6c 6c 73 28 31 2c 20 6c 61 73 74 63 6f 6c 20 2b 20 32 29 2e 56 61 6c 75 65 20 3d 20 22 54 6f 74 61 6c 49 6e 76 6f 69 63 65 56 61 6c 75 65 } //2 ThisWorkbook.Worksheets(i).Cells(1, lastcol + 2).Value = "TotalInvoiceValue
		$a_01_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 69 29 2e 43 65 6c 6c 73 28 72 2c 20 6c 61 73 74 63 6f 6c 20 2b 20 31 29 2e 56 61 6c 75 65 20 3d 20 74 6f 74 61 6c 73 70 6c 69 74 75 70 76 61 6c 75 65 } //2 ThisWorkbook.Worksheets(i).Cells(r, lastcol + 1).Value = totalsplitupvalue
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_192{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 70 76 74 54 61 62 6c 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 42 72 61 6e 64 20 53 68 65 65 74 4e 61 6d 65 4c 69 73 74 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 50 69 76 6f 74 54 61 62 6c 65 } //1 Set pvtTable = Worksheets("Brand SheetNameList").Range("A1").PivotTable
		$a_00_1 = {53 65 74 20 70 76 74 54 61 62 6c 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 57 48 53 4c 20 53 68 65 65 74 4e 61 6d 65 4c 69 73 74 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 50 69 76 6f 74 54 61 62 6c 65 } //1 Set pvtTable = Worksheets("WHSL SheetNameList").Range("A1").PivotTable
		$a_00_2 = {41 66 74 65 72 42 79 53 68 65 65 74 4e 61 6d 65 20 3d 20 22 54 6f 74 61 6c 20 53 68 65 65 74 4e 61 6d 65 4c 69 73 74 22 } //1 AfterBySheetName = "Total SheetNameList"
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 43 6f 70 79 44 61 74 61 28 42 79 56 61 6c 20 44 6f 6f 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Public Sub CopyData(ByVal DoorName As String)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_193{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 79 41 70 70 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 42 45 2e 56 42 50 72 6f 6a 65 63 74 73 28 22 4c 73 41 67 58 4c 42 22 29 2e 46 69 6c 65 4e 61 6d 65 2c 20 46 61 6c 73 65 } //1 myApp.Workbooks.Open Application.VBE.VBProjects("LsAgXLB").FileName, False
		$a_00_1 = {49 66 20 57 62 2e 4e 61 6d 65 20 3c 3e 20 22 4c 73 41 67 58 4c 42 2e 78 6c 61 22 20 54 68 65 6e } //1 If Wb.Name <> "LsAgXLB.xla" Then
		$a_00_2 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 6f 72 6b 62 6f 6f 6b 73 28 22 4c 73 41 67 58 4c 42 2e 78 6c 61 22 29 2e 50 61 74 68 20 26 20 22 5c 4c 73 41 67 58 4c 42 2e 78 6c 61 6d 22 } //1 Workbooks.Open Application.Workbooks("LsAgXLB.xla").Path & "\LsAgXLB.xlam"
		$a_00_3 = {72 65 74 20 3d 20 49 6e 53 74 72 28 31 2c 20 6c 43 65 6c 6c 2e 46 6f 72 6d 75 6c 61 2c 20 22 4c 73 41 67 58 4c 42 2e 78 6c 61 27 21 22 29 } //1 ret = InStr(1, lCell.Formula, "LsAgXLB.xla'!")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_194{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 6f 20 6f 76 65 72 72 69 64 65 20 73 65 74 20 60 4a 73 6f 6e 43 6f 6e 76 65 72 74 65 72 2e 4a 73 6f 6e 4f 70 74 69 6f 6e 73 2e 55 73 65 44 6f 75 62 6c 65 46 6f 72 4c 61 72 67 65 4e 75 6d 62 65 72 73 20 3d 20 54 72 75 65 60 } //1 to override set `JsonConverter.JsonOptions.UseDoubleForLargeNumbers = True`
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 56 42 41 2d 74 6f 6f 6c 73 2f 56 42 41 2d 55 74 63 43 6f 6e 76 65 72 74 65 72 } //1 https://github.com/VBA-tools/VBA-UtcConverter
		$a_00_2 = {45 72 72 2e 52 61 69 73 65 20 31 30 30 30 31 2c 20 22 4a 53 4f 4e 43 6f 6e 76 65 72 74 65 72 22 } //1 Err.Raise 10001, "JSONConverter"
		$a_00_3 = {45 72 72 2e 52 61 69 73 65 20 31 30 30 31 34 2c 20 22 55 74 63 43 6f 6e 76 65 72 74 65 72 2e 43 6f 6e 76 65 72 74 54 6f 49 73 6f 22 2c 20 22 49 53 4f 20 38 36 30 31 20 63 6f 6e 76 65 72 73 69 6f 6e 20 65 72 72 6f 72 3a 20 22 } //1 Err.Raise 10014, "UtcConverter.ConvertToIso", "ISO 8601 conversion error: "
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_195{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 6c 65 61 73 65 20 63 68 61 6e 67 65 20 74 68 65 20 6c 6f 63 61 74 69 6f 6e 20 6f 66 20 74 68 65 20 4d 61 70 70 69 6e 67 20 54 6f 6f 6c 20 70 61 63 6b 61 67 65 20 74 6f 20 61 20 64 69 72 65 63 74 6f 72 79 20 77 69 74 68 20 61 20 73 68 6f 72 74 65 72 20 70 61 74 68 2e } //1 Please change the location of the Mapping Tool package to a directory with a shorter path.
		$a_00_1 = {5a 69 70 5f 54 65 6d 70 6c 61 74 65 5f 50 61 74 68 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 4d 61 70 70 69 6e 67 54 6f 6f 6c 50 61 63 6b 61 67 65 5c 22 } //1 Zip_Template_Path = ThisWorkbook.Path & "\MappingToolPackage\"
		$a_00_2 = {5a 69 70 5f 4e 61 6d 65 20 3d 20 22 4d 61 70 70 69 6e 67 20 54 6f 6f 6c 20 50 61 63 6b 61 67 65 2e 7a 69 70 22 } //1 Zip_Name = "Mapping Tool Package.zip"
		$a_00_3 = {49 66 20 46 55 46 5f 54 61 67 5f 43 6f 6c 20 3d 20 46 55 46 5f 54 61 67 5f 42 61 73 69 63 5f 43 6f 6c 20 54 68 65 6e } //1 If FUF_Tag_Col = FUF_Tag_Basic_Col Then
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_196{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 67 6f 4f 41 54 6f 6f 6c 73 20 41 73 20 63 6c 73 4f 41 54 6f 6f 6c 73 } //1 Public goOATools As clsOATools
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 67 63 41 70 70 6c 69 63 61 74 69 6f 6e 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 4f 41 20 54 6f 6f 6c 73 22 20 27 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 6e 61 6d 65 } //1 Public Const gcApplicationName As String = "OA Tools" ' Application name
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 67 63 4f 41 43 6f 72 65 4c 69 62 46 69 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 4f 41 54 6f 6f 6c 73 2e 78 6c 61 6d 22 } //1 Public Const gcOACoreLibFileName As String = "OATools.xlam"
		$a_00_3 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 67 63 4f 41 53 6f 75 72 63 65 45 78 63 65 6c 52 69 62 62 6f 6e 57 6f 72 6b 62 6f 6f 6b 46 6f 6c 64 65 72 4e 61 6d 65 20 3d 20 22 4f 41 54 6f 6f 6c 73 4d 65 6e 75 22 } //1 Public Const gcOASourceExcelRibbonWorkbookFolderName = "OAToolsMenu"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_197{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 42 45 78 20 44 65 73 69 67 6e 20 54 6f 6f 6c 62 6f 78 22 29 2e 44 65 6c 65 74 65 } //1 Call CommandBars("BEx Design Toolbox").Delete
		$a_00_1 = {43 61 6c 6c 20 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 42 45 78 20 41 6e 61 6c 79 73 69 73 20 54 6f 6f 6c 62 6f 78 22 29 2e 44 65 6c 65 74 65 } //1 Call CommandBars("BEx Analysis Toolbox").Delete
		$a_00_2 = {53 65 74 20 70 41 64 64 69 6e 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 63 6f 6d 2e 73 61 70 2e 62 69 2e 65 74 2e 61 6e 61 6c 79 7a 65 72 2e 61 64 64 69 6e 2e 42 45 78 43 6f 6e 6e 65 63 74 22 29 } //1 Set pAddin = CreateObject("com.sap.bi.et.analyzer.addin.BExConnect")
		$a_00_3 = {53 65 74 20 47 65 74 42 45 78 20 3d 20 70 41 64 64 69 6e 2e 45 78 63 65 6c 49 6e 74 65 72 66 61 63 65 2e 57 6f 72 6b 62 6f 6f 6b 42 45 78 45 78 63 65 6c 41 70 70 6c 69 63 61 74 69 6f 6e 28 6c 4e 61 6d 65 29 } //1 Set GetBEx = pAddin.ExcelInterface.WorkbookBExExcelApplication(lName)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_198{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 74 72 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 22 43 3a 5c 41 6c 6f 63 61 6c 5c 43 68 61 72 61 63 74 65 72 69 73 61 74 69 6f 6e 20 66 69 6c 65 73 5c 54 52 41 43 45 31 2e 63 73 76 22 29 } //1 Set tr = Workbooks.Open("C:\Alocal\Characterisation files\TRACE1.csv")
		$a_00_1 = {53 65 74 20 74 72 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 22 43 3a 5c 41 6c 6f 63 61 6c 5c 43 68 61 72 61 63 74 65 72 69 73 61 74 69 6f 6e 20 66 69 6c 65 73 5c 54 52 41 43 45 32 2e 63 73 76 22 29 } //1 Set tr = Workbooks.Open("C:\Alocal\Characterisation files\TRACE2.csv")
		$a_00_2 = {74 72 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 54 52 41 43 45 31 22 29 2e 52 61 6e 67 65 28 22 42 34 3a 42 32 30 34 22 29 2e 43 6f 70 79 } //1 tr.Worksheets("TRACE1").Range("B4:B204").Copy
		$a_00_3 = {74 72 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 54 52 41 43 45 32 22 29 2e 52 61 6e 67 65 28 22 42 34 3a 42 32 30 34 22 29 2e 43 6f 70 79 } //1 tr.Worksheets("TRACE2").Range("B4:B204").Copy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_199{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 66 6e 61 6d 65 20 3d 20 22 63 3a 5c 4e 6f 74 42 61 63 6b 65 64 55 70 5c 77 64 70 76 73 30 39 37 2e 30 30 31 22 } //1 Const fname = "c:\NotBackedUp\wdpvs097.001"
		$a_00_1 = {50 72 69 6e 74 20 23 31 2c 20 22 73 65 6e 64 20 22 20 26 20 22 63 3a 5c 4e 6f 74 42 61 63 6b 65 64 55 70 5c 22 20 26 20 22 4f 46 46 4d 41 58 49 4e 31 2e 63 73 76 22 } //1 Print #1, "send " & "c:\NotBackedUp\" & "OFFMAXIN1.csv"
		$a_00_2 = {64 46 54 50 20 3d 20 22 2f 75 30 31 2f 61 70 70 2f 6d 73 64 70 66 69 6e 2f 64 61 74 61 2f 70 6c 64 61 74 61 2f 6d 61 73 74 65 72 2f 22 20 27 4b 45 41 20 35 2e 33 56 20 50 72 6f 64 75 63 74 69 6f 6e } //1 dFTP = "/u01/app/msdpfin/data/pldata/master/" 'KEA 5.3V Production
		$a_00_3 = {4d 73 67 42 6f 78 20 28 22 55 6e 61 62 6c 65 20 74 6f 20 72 65 63 6f 67 6e 69 73 65 20 79 6f 75 20 4b 45 41 20 75 73 65 72 20 49 44 2e 20 20 50 72 6f 63 65 73 73 20 74 65 72 6d 69 6e 61 74 65 64 2e 22 29 } //1 MsgBox ("Unable to recognise you KEA user ID.  Process terminated.")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_200{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 42 4c 4f 4f 4d 42 45 52 47 5f 4c 50 5f 4b 45 59 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 53 4f 46 54 57 41 52 45 5c 42 6c 6f 6f 6d 62 65 72 67 20 4c 2e 50 2e } //1 Public Const BLOOMBERG_LP_KEY As String = "SOFTWARE\Bloomberg L.P.
		$a_00_1 = {42 6c 6f 6f 6d 62 65 72 67 55 49 2e 78 6c 61 } //1 BloombergUI.xla
		$a_00_2 = {49 66 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 64 64 49 6e 73 28 69 29 2e 4e 61 6d 65 20 3d 20 22 42 6c 6f 6f 6d 62 65 72 67 55 49 50 50 54 22 20 54 68 65 6e } //1 If Application.AddIns(i).Name = "BloombergUIPPT" Then
		$a_00_3 = {43 61 6c 6c 42 6c 6f 6f 6d 62 65 72 67 55 49 4d 61 63 72 6f 20 22 43 6c 65 61 72 43 6f 6d 70 6f 6e 65 6e 74 53 74 61 74 65 22 2c 20 63 68 61 72 74 43 6f 6e 74 72 6f 6c 2e 75 73 65 72 44 61 74 61 20 2b 20 67 57 6f 72 6b 62 6f 6f 6b 4e 61 6d 65 20 2b 20 67 57 6f 72 6b 73 68 65 65 74 4e 61 6d 65 } //1 CallBloombergUIMacro "ClearComponentState", chartControl.userData + gWorkbookName + gWorksheetName
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_201{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 41 74 6c 61 73 49 6d 70 6f 72 74 28 73 74 72 52 65 70 6f 72 74 54 79 70 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Public Function AtlasImport(strReportType As String)
		$a_00_1 = {46 69 6c 65 53 70 65 63 20 3d 20 22 46 42 49 53 20 54 61 63 74 69 63 61 6c 20 52 65 70 6f 72 74 22 } //1 FileSpec = "FBIS Tactical Report"
		$a_00_2 = {45 78 74 72 61 63 74 50 61 74 68 20 3d 20 22 5c 5c 70 6f 69 73 65 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 6c 6f 63 61 6c 5c 64 61 74 61 5c 49 4e 44 5c 53 68 61 72 65 64 5c 54 72 61 6e 73 66 65 72 5c 41 54 4c 41 53 20 42 41 4d 5c 44 61 74 61 5c 22 } //1 ExtractPath = "\\poise.homeoffice.local\data\IND\Shared\Transfer\ATLAS BAM\Data\"
		$a_00_3 = {49 66 20 41 74 6c 61 73 49 6d 70 6f 72 74 28 53 68 65 65 74 32 2e 52 61 6e 67 65 28 22 56 5f 53 6e 41 5f 52 65 70 6f 72 74 54 79 70 65 22 29 2e 56 61 6c 75 65 29 20 3d 20 46 61 6c 73 65 20 54 68 65 6e } //1 If AtlasImport(Sheet2.Range("V_SnA_ReportType").Value) = False Then
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_202{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 74 72 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 22 43 3a 5c 41 6c 6f 63 61 6c 5c 43 68 61 72 61 63 74 65 72 69 73 61 74 69 6f 6e 20 66 69 6c 65 73 5c 54 52 41 43 45 31 2e 63 73 76 22 29 } //1 Set tr = Workbooks.Open("C:\Alocal\Characterisation files\TRACE1.csv")
		$a_00_1 = {77 62 2e 53 68 65 65 74 73 28 22 43 6f 6d 70 69 6c 65 64 20 44 61 74 61 22 29 2e 43 65 6c 6c 73 28 44 61 74 61 45 6e 74 72 79 2c 20 31 33 29 2e 56 61 6c 75 65 20 3d 20 42 61 6e 64 77 69 64 74 68 } //1 wb.Sheets("Compiled Data").Cells(DataEntry, 13).Value = Bandwidth
		$a_00_2 = {74 72 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 54 52 41 43 45 31 22 29 2e 52 61 6e 67 65 28 22 42 34 3a 42 32 30 34 22 29 2e 43 6f 70 79 } //1 tr.Worksheets("TRACE1").Range("B4:B204").Copy
		$a_00_3 = {77 62 2e 53 68 65 65 74 73 28 22 43 6f 6d 70 69 6c 65 64 20 44 61 74 61 22 29 2e 43 65 6c 6c 73 28 44 61 74 61 45 6e 74 72 79 2c 20 31 29 2e 53 65 6c 65 63 74 } //1 wb.Sheets("Compiled Data").Cells(DataEntry, 1).Select
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_203{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 41 50 50 5f 54 49 54 4c 45 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 49 52 45 53 53 20 41 64 64 2d 49 6e 22 } //1 Public Const APP_TITLE As String = "IRESS Add-In"
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 49 72 65 73 73 41 64 64 69 6e 50 72 65 66 65 72 65 6e 63 65 73 28 29 } //1 Public Sub IressAddinPreferences()
		$a_00_2 = {4d 73 67 42 6f 78 20 22 41 63 63 65 73 73 20 74 68 65 20 49 52 45 53 53 20 41 64 64 2d 49 6e 20 48 65 6c 70 20 62 79 20 6e 61 76 69 67 61 74 69 6e 67 20 74 6f 20 74 68 65 20 45 78 63 65 6c 20 49 6e 74 65 72 66 61 63 65 20 73 65 63 74 69 6f 6e 20 69 6e 20 74 68 65 20 49 52 45 53 53 20 48 65 6c 70 20 66 72 6f 6d 20 49 52 45 53 53 20 50 72 6f 2e 22 } //1 MsgBox "Access the IRESS Add-In Help by navigating to the Excel Interface section in the IRESS Help from IRESS Pro."
		$a_00_3 = {53 65 74 20 69 72 65 73 73 20 3d 20 4e 65 77 20 44 66 73 49 72 65 73 73 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //1 Set iress = New DfsIress.Application
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_204{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 45 75 72 6f 43 6f 6e 76 65 72 73 69 6f 6e 57 69 7a 61 72 64 28 29 } //1 Public Sub EuroConversionWizard()
		$a_00_1 = {22 45 55 52 20 2d 3e 20 41 54 53 22 2c 20 22 45 55 52 20 2d 3e 20 42 45 46 22 2c 20 22 45 55 52 20 2d 3e 20 43 59 50 22 } //1 "EUR -> ATS", "EUR -> BEF", "EUR -> CYP"
		$a_00_2 = {22 45 55 52 20 2d 3e 20 4e 4c 47 22 2c 20 22 45 55 52 20 2d 3e 20 50 54 45 22 2c 20 22 45 55 52 20 2d 3e 20 53 49 54 22 2c 20 22 45 55 52 20 2d 3e 20 53 4b 4b 22 } //1 "EUR -> NLG", "EUR -> PTE", "EUR -> SIT", "EUR -> SKK"
		$a_00_3 = {49 66 20 6d 5f 69 54 72 69 61 6e 67 53 65 74 20 3d 20 54 72 75 65 20 54 68 65 6e 20 66 72 6d 41 64 76 61 6e 63 65 64 2e 54 72 69 61 6e 67 50 72 65 63 20 3d 20 6d 5f 69 54 72 69 61 6e 67 50 72 65 63 } //1 If m_iTriangSet = True Then frmAdvanced.TriangPrec = m_iTriangPrec
		$a_00_4 = {6d 5f 69 53 6f 75 72 63 65 43 75 72 72 65 6e 63 79 20 3d 20 66 72 6d 2e 53 6f 75 72 63 65 43 75 72 72 65 6e 63 79 } //1 m_iSourceCurrency = frm.SourceCurrency
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_205{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 75 74 68 6f 72 20 2d 20 50 72 61 73 68 61 6e 74 20 44 65 73 68 70 61 6e 64 65 } //1 Author - Prashant Deshpande
		$a_00_1 = {50 72 69 76 61 74 65 20 50 72 6f 70 65 72 74 79 20 53 65 74 20 49 56 42 53 41 58 43 6f 6e 74 65 6e 74 48 61 6e 64 6c 65 72 5f 64 6f 63 75 6d 65 6e 74 4c 6f 63 61 74 6f 72 28 42 79 56 61 6c 20 52 48 53 20 41 73 20 4d 53 58 4d 4c 32 2e 49 56 42 53 41 58 4c 6f 63 61 74 6f 72 29 } //1 Private Property Set IVBSAXContentHandler_documentLocator(ByVal RHS As MSXML2.IVBSAXLocator)
		$a_00_2 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 43 6f 6e 76 65 72 74 58 53 44 54 79 70 65 54 6f 56 42 41 54 79 70 65 28 73 58 53 44 54 79 70 65 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 53 74 72 69 6e 67 } //1 Private Function ConvertXSDTypeToVBAType(sXSDType As String) As String
		$a_00_3 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 4d 65 73 73 61 67 65 73 28 29 20 41 73 20 42 6e 65 56 42 41 4d 65 73 73 61 67 65 73 } //1 Public Property Get Messages() As BneVBAMessages
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_206{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {72 61 6e 67 65 4e 61 6d 65 20 3d 20 22 7a 44 6c 67 4f 75 74 59 65 61 72 73 22 } //1 rangeName = "zDlgOutYears"
		$a_00_1 = {63 6f 6c 4e 6f 20 3d 20 72 61 6e 67 65 28 22 7a 44 6c 67 4f 75 74 59 65 61 72 73 22 29 2e 43 6f 6c 75 6d 6e 73 28 72 61 6e 67 65 28 22 7a 44 6c 67 4f 75 74 59 65 61 72 73 22 29 2e 43 6f 6c 75 6d 6e 73 2e 43 6f 75 6e 74 29 2e 43 6f 6c 75 6d 6e 20 2b 20 31 } //1 colNo = range("zDlgOutYears").Columns(range("zDlgOutYears").Columns.Count).Column + 1
		$a_00_2 = {72 6f 77 4f 66 66 73 65 74 20 3d 20 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 52 6f 77 73 28 31 29 2e 72 6f 77 } //1 rowOffset = range("zDlgPeriods").Rows(1).row
		$a_00_3 = {63 6f 6c 4e 6f 20 3d 20 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 43 6f 6c 75 6d 6e 73 28 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 43 6f 6c 75 6d 6e 73 2e 43 6f 75 6e 74 29 2e 43 6f 6c 75 6d 6e 20 2b 20 31 } //1 colNo = range("zDlgPeriods").Columns(range("zDlgPeriods").Columns.Count).Column + 1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_207{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 42 61 73 69 63 20 44 65 74 61 69 6c 73 20 4e 65 77 20 4d 65 6d 62 65 72 73 22 } //2 SHEETName = "Basic Details New Members"
		$a_00_1 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 42 61 73 69 63 20 44 65 74 61 69 6c 73 20 45 78 69 73 74 69 6e 67 20 4d 65 6d 62 65 72 73 22 } //2 SHEETName = "Basic Details Existing Members"
		$a_00_2 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 53 65 72 76 69 63 65 20 48 69 73 74 6f 72 79 20 43 72 69 62 20 53 68 65 65 74 22 } //2 SHEETName = "Service History Crib Sheet"
		$a_00_3 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 57 50 53 20 52 61 74 65 20 48 69 73 74 6f 72 79 22 } //2 SHEETName = "WPS Rate History"
		$a_00_4 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 41 56 43 20 48 69 73 74 6f 72 79 22 } //2 SHEETName = "AVC History"
		$a_00_5 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 42 65 6e 65 66 69 63 69 61 72 79 20 44 65 74 61 69 6c 73 22 } //2 SHEETName = "Beneficiary Details"
		$a_00_6 = {53 75 62 20 43 6f 6e 74 72 6f 6c 54 6f 74 61 6c 73 } //2 Sub ControlTotals
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2) >=14
 
}
rule _#ASRWin32ApiMacroExclusion_208{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {51 55 41 4c 49 54 59 20 4d 41 4e 41 47 45 4d 45 4e 54 5c 30 39 20 43 68 65 63 6b 20 74 68 65 20 43 68 65 63 6b 65 72 5c 70 72 6f 66 2d 6f 72 6d 61 73 20 61 6e 64 20 6f 6c 64 20 73 68 65 65 74 73 5c 43 54 43 20 44 69 73 70 75 74 65 2d 51 75 65 72 79 20 52 65 73 6f 6c 75 74 69 6f 6e 20 50 72 6f 66 6f 72 6d 61 2e 64 6f 63 78 } //2 QUALITY MANAGEMENT\09 Check the Checker\prof-ormas and old sheets\CTC Dispute-Query Resolution Proforma.docx
		$a_00_1 = {53 65 6e 74 4f 6e 42 65 68 61 6c 66 4f 66 4e 61 6d 65 20 3d 20 22 43 65 6e 74 72 61 6c 4f 70 65 72 61 74 69 6f 6e 73 51 40 68 6d 70 6f 2e 67 6f 76 2e 75 6b 22 } //2 SentOnBehalfOfName = "CentralOperationsQ@hmpo.gov.uk"
		$a_00_2 = {54 6f 20 3d 20 22 72 6f 78 61 6e 6e 65 2e 6d 63 63 75 65 40 68 6d 70 6f 2e 67 6f 76 2e 75 6b 3b 73 68 69 72 6c 65 79 2e 72 6f 62 69 6e 73 6f 6e 40 68 6d 70 6f 2e 67 6f 76 2e 75 6b 3b 6d 61 72 6b 2e 77 6f 6f 64 73 40 68 6d 70 6f 2e 67 6f 76 2e 75 6b 22 } //2 To = "roxanne.mccue@hmpo.gov.uk;shirley.robinson@hmpo.gov.uk;mark.woods@hmpo.gov.uk"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_209{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 4b 52 4f 4e 45 53 22 29 2e 43 6f 6e 74 72 6f 6c 73 28 22 45 78 65 63 75 74 65 22 29 2e 44 65 6c 65 74 65 } //1 Application.CommandBars("KRONES").Controls("Execute").Delete
		$a_00_1 = {56 69 65 77 45 78 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 65 6c 6e 72 75 6e 22 29 20 2b 20 22 5c 76 69 65 77 2e 65 78 65 20 2d 70 20 22 20 2b 20 56 6f 72 6c 61 67 65 } //1 ViewExe = Environ("elnrun") + "\view.exe -p " + Vorlage
		$a_00_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d 50 61 74 68 6e 61 6d 65 20 2b 20 22 5c 63 6f 70 79 6c 69 73 74 5f 73 70 73 2e 78 6c 73 22 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 78 6c 4e 6f 72 6d 61 6c } //1 ActiveWorkbook.SaveAs FileName:=Pathname + "\copylist_sps.xls", FileFormat:=xlNormal
		$a_00_3 = {53 65 74 20 6f 42 61 72 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 4b 52 4f 4e 45 53 22 } //1 Set oBar = Application.CommandBars("KRONES"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_210{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 79 46 69 6c 65 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 41 75 74 6f 6d 61 74 65 64 4d 65 61 73 75 72 65 6d 65 6e 74 73 2e 74 78 74 22 } //1 MyFile = ThisWorkbook.Path & "\AutomatedMeasurements.txt"
		$a_00_1 = {53 75 62 20 6d 79 63 6f 6c 6c 65 63 74 69 6f 6e 70 72 6f 63 65 64 75 72 65 28 29 } //1 Sub mycollectionprocedure()
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 54 69 6d 65 20 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 30 3a 30 30 3a 30 32 22 29 2c 20 22 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 6d 79 63 6f 6c 6c 65 63 74 69 6f 6e 70 72 6f 63 65 64 75 72 65 22 } //1 Application.OnTime Now + TimeValue("00:00:02"), "ThisWorkbook.mycollectionprocedure"
		$a_00_3 = {4d 73 67 42 6f 78 20 28 22 49 6e 76 61 6c 69 64 20 46 69 6c 65 6e 61 6d 65 3a 20 20 4c 61 73 74 20 36 20 63 68 61 72 61 63 74 65 72 73 20 6f 66 20 66 69 6c 65 6e 61 6d 65 20 61 72 65 20 6e 6f 74 20 78 2e 78 6c 73 6d 21 22 29 } //1 MsgBox ("Invalid Filename:  Last 6 characters of filename are not x.xlsm!")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_211{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 65 62 61 64 69 53 68 65 65 74 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 53 68 2e 43 6f 64 65 4e 61 6d 65 20 26 20 22 5f 57 45 42 41 44 49 22 29 } //1 webadiSheet = ActiveWorkbook.CustomDocumentProperties(Sh.CodeName & "_WEBADI")
		$a_00_1 = {43 6f 6e 73 74 20 50 52 4f 44 55 43 54 5f 52 45 4c 45 41 53 45 5f 4c 41 42 45 4c 20 3d 20 22 31 32 2e 30 2e 30 2e 30 3a 20 46 72 69 64 61 79 20 46 65 62 75 72 61 72 79 20 31 30 2c 20 32 30 30 36 22 } //1 Const PRODUCT_RELEASE_LABEL = "12.0.0.0: Friday Feburary 10, 2006"
		$a_00_2 = {62 6c 6f 63 6b 41 76 61 69 6c 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 42 4c 4f 43 4b 22 20 26 20 62 6c 6f 63 6b 49 6e 64 65 78 29 } //1 blockAvail = ActiveWorkbook.CustomDocumentProperties("BLOCK" & blockIndex)
		$a_00_3 = {44 69 6d 20 6d 5f 52 69 62 62 6f 6e 20 41 73 20 49 52 69 62 62 6f 6e 55 49 } //1 Dim m_Ribbon As IRibbonUI
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_212{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 43 6f 6d 6d 61 6e 64 54 65 78 74 20 3d 20 22 73 70 46 58 45 58 50 44 65 74 61 69 6c 46 78 54 72 61 6e 73 61 63 74 69 6f 6e 22 } //1 com.CommandText = "spFXEXPDetailFxTransaction"
		$a_00_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 47 65 74 46 58 48 65 67 64 65 73 46 72 6f 6d 44 65 61 6c 73 44 65 74 61 69 6c 28 42 79 56 61 6c 20 62 72 61 6e 63 68 49 44 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 53 74 61 72 74 44 61 74 65 20 41 73 20 44 61 74 65 2c 20 42 79 56 61 6c 20 45 6e 64 44 61 74 65 20 41 73 20 44 61 74 65 29 } //1 Public Function GetFXHegdesFromDealsDetail(ByVal branchID As Long, ByVal StartDate As Date, ByVal EndDate As Date)
		$a_00_2 = {43 6f 6d 6d 61 6e 64 54 65 78 74 20 3d 20 22 73 70 46 58 45 58 50 47 65 74 4d 6f 6e 74 68 6c 79 52 65 73 75 6c 74 22 } //1 CommandText = "spFXEXPGetMonthlyResult"
		$a_00_3 = {5c 5c 73 74 6f 6c 74 7a 5c 4b 76 61 6e 74 5c 44 65 76 5c 48 65 6e 72 69 6b 5c 46 58 20 45 78 70 6f 5c 54 65 73 74 50 75 62 6c 69 73 68 5c } //1 \\stoltz\Kvant\Dev\Henrik\FX Expo\TestPublish\
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_213{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 73 75 6d 70 61 67 65 74 62 6c 2e 56 42 5f 44 65 73 63 72 69 70 74 69 6f 6e 20 3d 20 22 4d 61 63 72 6f 20 72 65 63 6f 72 64 65 64 20 37 2f 32 32 2f 30 32 20 62 79 20 6d 75 72 74 68 61 22 } //2 Attribute sumpagetbl.VB_Description = "Macro recorded 7/22/02 by murtha"
		$a_00_1 = {49 66 20 44 69 72 28 22 63 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 61 64 6f 62 65 5c 61 63 72 6f 62 61 74 20 36 2e 30 5c 61 63 72 6f 62 61 74 5c 61 63 72 6f 62 61 74 2e 65 78 65 22 2c 20 76 62 4e 6f 72 6d 61 6c 29 20 3d 20 22 22 20 54 68 65 6e } //2 If Dir("c:\program files\adobe\acrobat 6.0\acrobat\acrobat.exe", vbNormal) = "" Then
		$a_00_2 = {49 66 20 44 69 72 28 22 63 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 61 64 6f 62 65 5c 61 63 72 6f 62 61 74 20 36 2e 30 5c 50 44 46 4d 61 6b 65 72 5c 4f 66 66 69 63 65 5c 50 44 46 4d 61 6b 65 72 41 2e 64 6f 74 22 2c 20 76 62 4e 6f 72 6d 61 6c 29 20 3d 20 22 22 20 54 68 65 6e } //2 If Dir("c:\program files\adobe\acrobat 6.0\PDFMaker\Office\PDFMakerA.dot", vbNormal) = "" Then
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_214{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 50 72 69 6e 74 22 29 2e 53 68 61 70 65 73 28 22 70 69 63 5f 54 52 36 32 30 22 29 2e 56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 } //1 ThisWorkbook.Sheets("Print").Shapes("pic_TR620").Visible = False
		$a_00_1 = {46 69 6c 65 43 6f 6e 74 65 6e 74 73 20 3d 20 72 65 70 6c 61 63 65 28 46 69 6c 65 43 6f 6e 74 65 6e 74 73 2c 20 22 64 78 66 5f 42 65 61 72 69 6e 67 5f 44 22 2c 20 52 61 6e 67 65 28 22 76 61 6c 5f 42 65 61 72 69 6e 67 5f 44 22 29 2e 76 61 6c 75 65 29 } //1 FileContents = replace(FileContents, "dxf_Bearing_D", Range("val_Bearing_D").value)
		$a_00_2 = {77 62 2e 53 68 65 65 74 73 28 22 50 72 69 6e 74 22 29 2e 52 61 6e 67 65 28 22 76 61 6c 5f 54 65 6d 70 65 72 61 74 75 72 65 43 6c 61 73 73 22 29 } //1 wb.Sheets("Print").Range("val_TemperatureClass")
		$a_00_3 = {52 61 6e 67 65 28 22 76 61 6c 5f 50 6f 6c 65 70 61 69 72 73 22 29 2e 76 61 6c 75 65 20 3d 20 49 74 65 6d 44 61 74 61 28 22 50 6f 6c 65 20 70 61 69 72 73 22 29 } //1 Range("val_Polepairs").value = ItemData("Pole pairs")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_215{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {55 6d 67 65 62 75 6e 67 73 2e 53 54 61 62 5f 32 5f 41 20 3d 20 54 4d 61 72 6b 5f 41 6e 66 5f 41 6e 66 20 2b 20 54 72 69 6d 28 22 48 52 54 41 42 45 4c 4c 45 22 29 20 2b 20 54 4d 61 72 6b 5f 45 6e 64 65 } //1 Umgebungs.STab_2_A = TMark_Anf_Anf + Trim("HRTABELLE") + TMark_Ende
		$a_00_1 = {46 75 6e 63 74 69 6f 6e 20 62 77 45 72 73 65 74 7a 65 6e 28 73 74 72 45 69 6e 67 61 6e 67 20 41 73 20 53 74 72 69 6e 67 2c 20 73 74 72 4e 45 5a 29 20 41 73 20 53 74 72 69 6e 67 } //1 Function bwErsetzen(strEingang As String, strNEZ) As String
		$a_00_2 = {49 66 20 44 6f 6b 31 2e 42 6f 6f 6b 6d 61 72 6b 73 2e 45 78 69 73 74 73 28 22 4d 4b 41 52 54 45 5f 54 41 42 22 29 20 3d 20 54 72 75 65 20 54 68 65 6e } //1 If Dok1.Bookmarks.Exists("MKARTE_TAB") = True Then
		$a_00_3 = {46 75 6e 63 74 69 6f 6e 20 53 70 61 6c 74 65 6e 41 6e 7a 28 73 74 72 53 50 54 4d 61 72 6b 65 20 41 73 20 53 74 72 69 6e 67 2c 20 73 74 72 53 75 63 68 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 49 6e 74 65 67 65 72 } //1 Function SpaltenAnz(strSPTMarke As String, strSuch As String) As Integer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_216{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_00_0 = {57 53 20 3d 20 22 4d 6f 74 6f 72 20 63 68 61 72 61 63 74 65 72 69 73 74 69 63 73 22 } //2 WS = "Motor characteristics"
		$a_00_1 = {50 6c 65 61 73 65 20 70 75 74 20 69 6e 20 74 68 65 20 70 61 73 73 77 6f 72 64 20 74 6f 20 67 65 74 20 74 6f 20 74 68 65 20 65 6e 67 69 6e 65 65 72 69 6e 67 20 6d 6f 64 65 2e 22 2c 20 22 50 61 73 73 77 6f 72 74 61 62 66 72 61 67 65 20 2f 20 70 61 73 73 77 6f 72 64 20 72 65 71 75 65 73 74 22 2c 20 22 2a 2a 2a 2a 2a 22 } //2 Please put in the password to get to the engineering mode.", "Passwortabfrage / password request", "*****"
		$a_00_2 = {57 6f 72 6b 73 68 65 65 74 73 28 22 41 63 74 75 61 74 6f 72 20 63 68 61 72 61 63 74 65 72 69 73 74 69 63 73 22 29 } //2 Worksheets("Actuator characteristics")
		$a_00_3 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4b 65 6e 6e 6c 69 6e 69 65 6e 62 65 72 65 63 68 6e 75 6e 67 22 } //2 Attribute VB_Name = "Kennlinienberechnung"
		$a_00_4 = {46 75 6e 63 74 69 6f 6e 20 4b 65 6e 6e 6c 69 6e 69 65 5f 62 65 72 65 63 68 6e 65 6e 28 29 } //2 Function Kennlinie_berechnen()
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_217{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 65 78 63 65 6c 2d 6d 61 6c 69 6e 2e 63 6f 6d } //1 http://excel-malin.com
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 78 63 65 6c 2d 70 72 61 74 69 71 75 65 2e 63 6f 6d 2f 66 72 2f 61 73 74 75 63 65 73 5f 76 62 61 2f 72 65 63 68 65 72 63 68 65 2d 74 61 62 6c 65 61 75 2d 61 72 72 61 79 2e 70 68 70 } //1 https://www.excel-pratique.com/fr/astuces_vba/recherche-tableau-array.php
		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6d 6d 65 6e 74 63 61 6d 61 72 63 68 65 2e 6e 65 74 2f 66 6f 72 75 6d 2f 61 66 66 69 63 68 2d 33 31 34 33 32 34 31 33 2d 69 6d 70 6f 72 74 61 74 69 6f 6e 2d 64 65 2d 64 6f 6e 6e 65 65 73 2d 73 61 6e 73 2d 64 6f 75 62 6c 6f 6e 73 23 39 } //1 http://www.commentcamarche.net/forum/affich-31432413-importation-de-donnees-sans-doublons#9
		$a_00_3 = {68 74 74 70 3a 2f 2f 61 6b 6f 65 62 65 6c 2e 66 72 65 65 2e 66 72 2f 77 61 6e 61 64 6f 6f 2f 63 61 74 68 79 2f 76 62 61 2f 6f 62 6a 5f 78 6c 5f 67 72 61 70 68 5f 73 65 72 69 65 73 2e 68 74 6d } //1 http://akoebel.free.fr/wanadoo/cathy/vba/obj_xl_graph_series.htm
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_218{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 54 45 4d 50 5f 53 48 45 45 54 5f 4e 41 4d 45 5f 43 4f 56 45 52 29 2e 50 72 6f 74 65 63 74 20 50 61 73 73 77 6f 72 64 3a 3d 50 52 4f 54 45 43 54 5f 50 41 53 53 } //1 ThisWorkbook.Worksheets(TEMP_SHEET_NAME_COVER).Protect Password:=PROTECT_PASS
		$a_00_1 = {73 50 61 74 68 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 72 69 74 65 2e 74 78 74 22 } //1 sPath = ThisWorkbook.Path & "\" & "Write.txt"
		$a_00_2 = {43 61 6c 6c 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 54 45 4d 50 5f 53 48 45 45 54 5f 4e 41 4d 45 5f 53 41 54 49 53 46 59 29 2e 44 65 6c 65 74 65 53 61 74 69 73 66 79 53 6b 69 70 } //1 Call ThisWorkbook.Worksheets(TEMP_SHEET_NAME_SATISFY).DeleteSatisfySkip
		$a_00_3 = {49 66 20 28 43 68 65 63 6b 56 61 6c 69 64 61 74 69 6f 6e 28 6f 53 68 65 65 74 2c 20 6c 52 6f 77 2c 20 52 45 53 41 52 43 48 5f 43 4f 4c 55 4d 4e 5f 41 4e 53 57 45 52 29 29 20 54 68 65 6e } //1 If (CheckValidation(oSheet, lRow, RESARCH_COLUMN_ANSWER)) Then
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_219{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {74 6d 70 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 44 66 6d 5c 54 45 4c 4e 2e 74 78 74 22 } //1 tmp = "C:\Program Files (x86)\Dfm\TELN.txt"
		$a_00_1 = {49 66 20 28 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 3d 20 22 50 45 30 31 38 30 30 38 35 33 22 20 4f 72 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 3d 20 22 65 70 65 63 6f 22 29 20 54 68 65 6e } //1 If (Environ("UserName") = "PE01800853" Or Environ("UserName") = "epeco") Then
		$a_00_2 = {74 6d 70 20 3d 20 22 43 3a 5c 5f 6d 69 74 5c 54 6f 6f 6c 73 5c 22 20 26 20 70 72 67 4e 61 6d 65 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 53 65 70 61 72 61 74 6f 72 } //1 tmp = "C:\_mit\Tools\" & prgName & Application.PathSeparator
		$a_00_3 = {76 62 43 72 69 74 69 63 61 6c 20 4f 72 20 76 62 4f 4b 4f 6e 6c 79 2c 20 22 53 6f 72 72 79 2c 20 74 68 69 73 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 69 73 20 57 6f 72 6b 69 6e 67 20 4f 4e 4c 59 20 66 72 6f 6d 20 22 20 26 20 74 6d 70 } //1 vbCritical Or vbOKOnly, "Sorry, this Application is Working ONLY from " & tmp
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_220{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 6f 6c 76 65 72 50 61 74 68 20 26 20 22 21 53 6f 6c 76 65 72 4f 6b 22 2c 20 22 24 42 24 32 36 22 2c 20 32 2c 20 30 2c 20 22 24 42 24 31 35 3a 24 42 24 31 39 22 2c 20 31 2c 20 22 47 52 47 20 4e 6f 6e 6c 69 6e 65 61 72 22 } //2 Application.Run SolverPath & "!SolverOk", "$B$26", 2, 0, "$B$15:$B$19", 1, "GRG Nonlinear"
		$a_00_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 6f 6c 76 65 72 50 61 74 68 20 26 20 22 21 53 6f 6c 76 65 72 52 65 73 65 74 22 } //2 Application.Run SolverPath & "!SolverReset"
		$a_00_2 = {52 65 63 6f 6d 6d 65 6e 64 65 64 20 73 65 74 74 69 6e 67 73 20 5b 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 65 6e 2d 75 73 2f 6d 69 63 72 6f 73 6f 66 74 2d 33 36 35 2f 62 6c 6f 67 2f 32 30 30 39 2f 30 33 2f 31 32 2f 65 78 63 65 6c 2d 76 62 61 2d 70 65 72 66 6f 72 6d 61 6e 63 65 2d 63 6f 64 69 6e 67 2d 62 65 73 74 2d 70 72 61 63 74 69 63 65 73 2f 5d } //2 Recommended settings [https://www.microsoft.com/en-us/microsoft-365/blog/2009/03/12/excel-vba-performance-coding-best-practices/]
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_221{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4a 6f 75 72 6e 61 6c 5f 6e 61 6d 65 20 3d 20 22 55 4b 42 41 20 31 30 30 31 32 38 32 36 20 41 44 49 20 22 20 26 20 46 6f 72 6d 61 74 28 44 61 74 65 2c 20 22 44 44 4d 4d 59 59 22 29 } //1 Journal_name = "UKBA 10012826 ADI " & Format(Date, "DDMMYY")
		$a_00_1 = {43 6f 6e 73 74 20 50 52 4f 44 55 43 54 5f 43 4f 44 45 5f 4c 41 42 45 4c 20 3d 20 22 38 2e 34 2e 31 2e 33 38 22 } //1 Const PRODUCT_CODE_LABEL = "8.4.1.38"
		$a_00_2 = {43 6f 6e 73 74 20 50 52 4f 44 55 43 54 5f 52 45 4c 45 41 53 45 5f 4c 41 42 45 4c 20 3d 20 22 38 2e 34 2e 31 2e 33 38 20 57 65 64 6e 65 73 64 61 79 20 33 31 20 4a 61 6e 75 61 72 79 20 32 30 30 37 22 } //1 Const PRODUCT_RELEASE_LABEL = "8.4.1.38 Wednesday 31 January 2007"
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 43 72 65 61 74 65 4c 61 79 6f 75 74 5f 4f 76 65 72 66 6c 6f 77 5f 32 30 30 5f 42 4e 45 5f 48 4f 46 41 53 5f 32 28 78 6c 61 70 70 20 41 73 20 41 70 70 6c 69 63 61 74 69 6f 6e 2c 20 4c 61 79 6f 75 74 53 68 65 65 74 20 41 73 20 57 6f 72 6b 73 68 65 65 74 29 } //1 Public Sub CreateLayout_Overflow_200_BNE_HOFAS_2(xlapp As Application, LayoutSheet As Worksheet)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_222{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 28 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 46 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 5c 64 61 74 61 5c 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 73 74 61 74 69 63 2e 78 6c 73 78 22 29 } //1 Workbooks.Open ("\\brummer.se\bfs\BFS-Operations\Function sheet\data\function sheet static.xlsx")
		$a_00_1 = {49 66 20 66 75 6e 64 20 3d 20 22 54 61 6c 61 72 69 75 6d 22 20 4f 72 20 66 75 6e 64 20 3d 20 22 46 43 43 22 20 54 68 65 6e } //1 If fund = "Talarium" Or fund = "FCC" Then
		$a_00_2 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 64 61 74 61 20 50 50 2e 78 6c 73 78 22 29 2e 43 6c 6f 73 65 20 28 46 61 6c 73 65 29 } //1 Workbooks("function sheet data PP.xlsx").Close (False)
		$a_00_3 = {70 61 74 68 20 3d 20 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 4d 4f 5c 46 75 6e 63 74 69 6f 6e 20 53 68 65 65 74 5c 41 72 63 68 69 76 65 5c 22 } //1 path = "\\brummer.se\bfs\BFS-Operations\MO\Function Sheet\Archive\"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_223{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 46 6f 6c 6c 6f 77 48 79 70 65 72 6c 69 6e 6b 20 41 64 64 72 65 73 73 3a 3d 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 74 65 61 63 68 65 72 73 70 65 6e 73 69 6f 6e 73 2e 63 6f 2e 75 6b 2f 6d 63 72 67 75 69 64 65 73 22 } //2 ThisWorkbook.FollowHyperlink Address:="https://www.teacherspensions.co.uk/mcrguides"
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 62 74 6e 56 69 65 77 55 49 5f 53 65 63 42 5f 43 6c 69 63 6b 28 29 } //2 Private Sub btnViewUI_SecB_Click()
		$a_00_2 = {69 6e 74 41 6e 73 20 3d 20 4d 73 67 42 6f 78 28 70 72 6f 6d 70 74 3a 3d 22 54 68 65 20 63 6f 6e 74 72 69 62 75 74 69 6f 6e 20 61 6d 6f 75 6e 74 73 20 77 69 6c 6c 20 62 65 20 67 65 6e 65 72 61 74 65 64 20 61 6e 64 20 76 61 6c 69 64 61 74 65 64 20 62 61 73 65 64 20 6f 6e 20 74 68 65 20 6d 65 6d 62 65 72 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 79 6f 75 20 68 61 76 65 20 70 72 6f 76 69 64 65 64 20 69 6e 20 53 65 63 74 69 6f 6e 20 41 2e 22 } //2 intAns = MsgBox(prompt:="The contribution amounts will be generated and validated based on the member information you have provided in Section A."
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_224{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_00_0 = {44 65 76 65 6c 6f 70 65 64 20 62 79 20 4d 69 63 68 61 65 6c 20 45 69 66 66 6c 61 65 6e 64 65 72 20 2f 20 41 45 20 53 6f 66 74 77 61 72 65 20 53 6f 6c 75 74 69 6f 6e 73 } //5 Developed by Michael Eifflaender / AE Software Solutions
		$a_00_1 = {50 75 62 6c 69 63 20 74 4d 69 6c 65 73 74 6f 6e 65 73 28 35 30 30 30 29 20 41 73 20 54 6d 69 6c 65 73 74 6f 6e 65 } //1 Public tMilestones(5000) As Tmilestone
		$a_00_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 61 63 62 44 6f 65 73 4f 62 6a 45 78 69 73 74 28 6f 62 6a 29 } //1 Public Function acbDoesObjExist(obj)
		$a_00_3 = {50 75 62 6c 69 63 20 6f 62 6a 50 50 54 20 41 73 20 4f 62 6a 65 63 74 20 27 50 6f 77 65 72 50 6f 69 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //1 Public objPPT As Object 'PowerPoint.Application
		$a_00_4 = {46 75 6e 63 74 69 6f 6e 20 61 62 62 72 65 76 69 61 74 65 5f 4d 53 5f 4e 61 6d 65 28 6d 73 4e 61 6d 65 29 } //1 Function abbreviate_MS_Name(msName)
		$a_00_5 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 74 72 69 6d 54 69 6d 65 28 64 61 74 65 5f 77 69 74 68 5f 74 69 6d 65 29 } //1 Public Function trimTime(date_with_time)
	condition:
		((#a_00_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=9
 
}
rule _#ASRWin32ApiMacroExclusion_225{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 55 42 4b 45 59 20 3d 20 22 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 54 47 44 6f 63 58 2e 65 78 65 22 } //1 Public Const SUBKEY = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ITGDocX.exe"
		$a_00_1 = {73 74 72 4d 73 67 20 3d 20 73 74 72 4d 73 67 20 26 20 22 2d 20 49 54 20 4e 65 74 20 44 65 73 69 67 6e 20 41 70 70 20 4e 6f 74 20 49 6e 73 74 61 6c 6c 65 64 2e 22 } //1 strMsg = strMsg & "- IT Net Design App Not Installed."
		$a_00_2 = {53 65 74 20 76 69 73 41 64 64 4f 6e 20 3d 20 56 69 73 69 6f 2e 41 64 64 6f 6e 73 2e 41 64 64 28 73 74 72 41 70 70 50 61 74 68 20 26 20 22 49 54 47 44 6f 63 58 2e 65 78 65 22 29 } //1 Set visAddOn = Visio.Addons.Add(strAppPath & "ITGDocX.exe")
		$a_00_3 = {56 69 73 69 6f 2e 41 64 64 6f 6e 73 2e 49 74 65 6d 28 73 74 72 41 70 70 50 61 74 68 20 26 20 22 49 54 47 44 6f 63 58 2e 65 78 65 22 29 2e 52 75 6e 20 28 22 44 65 76 69 63 65 53 70 65 63 22 29 } //1 Visio.Addons.Item(strAppPath & "ITGDocX.exe").Run ("DeviceSpec")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_226{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 46 69 6c 65 20 3d 20 4d 61 6b 65 46 69 6c 65 4e 61 6d 65 28 57 6f 72 6b 73 68 65 65 74 73 28 22 53 65 6d 69 2d 61 6e 6e 75 61 6c 22 29 2e 52 61 6e 67 65 28 22 52 65 70 6f 72 74 5f 50 65 72 69 6f 64 22 29 2c 20 22 46 58 5f 54 75 72 6e 6f 76 65 72 5f 53 75 72 76 65 79 22 2c 20 57 6f 72 6b 73 68 65 65 74 73 28 22 53 65 6d 69 2d 61 6e 6e 75 61 6c 22 29 2e 52 61 6e 67 65 28 22 49 6e 73 74 69 74 75 74 69 6f 6e 5f 43 6f 64 65 22 29 2c 20 22 2e 78 6c 73 22 29 } //1 cFile = MakeFileName(Worksheets("Semi-annual").Range("Report_Period"), "FX_Turnover_Survey", Worksheets("Semi-annual").Range("Institution_Code"), ".xls")
		$a_00_1 = {49 66 20 28 49 6e 53 74 72 28 31 2c 20 6e 2e 4e 61 6d 65 2c 20 22 4f 42 52 44 4c 55 53 44 48 4b 44 22 29 20 3e 3d 20 31 29 20 54 68 65 6e } //1 If (InStr(1, n.Name, "OBRDLUSDHKD") >= 1) Then
		$a_00_2 = {77 73 2e 43 65 6c 6c 73 28 6e 52 6f 77 2c 20 69 29 2e 4e 61 6d 65 20 3d 20 22 46 58 43 5f 53 57 37 44 4c 22 20 2b 20 4c 65 66 74 28 77 73 2e 43 65 6c 6c 73 28 63 52 6f 77 2c 20 69 29 2e 56 61 6c 75 65 2c 20 33 29 } //1 ws.Cells(nRow, i).Name = "FXC_SW7DL" + Left(ws.Cells(cRow, i).Value, 3)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_227{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {78 41 6e 6f 76 61 31 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 47 65 74 4d 61 63 72 6f 52 65 67 49 64 28 22 66 6e 41 6e 6f 76 61 31 22 29 2c 20 69 6e 70 72 6e 67 2c 20 6f 75 74 72 6e 67 2c 20 67 72 6f 75 70 65 64 2c 20 6c 61 62 65 6c 73 2c 20 61 6c 70 68 61 29 } //2 xAnova1 = Application.Run(GetMacroRegId("fnAnova1"), inprng, outrng, grouped, labels, alpha)
		$a_00_1 = {78 41 6e 6f 76 61 31 51 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 47 65 74 4d 61 63 72 6f 52 65 67 49 64 28 22 66 6e 41 6e 6f 76 61 31 51 22 29 2c 20 69 6e 70 72 6e 67 2c 20 6f 75 74 72 6e 67 2c 20 67 72 6f 75 70 65 64 2c 20 6c 61 62 65 6c 73 2c 20 61 6c 70 68 61 29 } //2 xAnova1Q = Application.Run(GetMacroRegId("fnAnova1Q"), inprng, outrng, grouped, labels, alpha)
		$a_00_2 = {78 41 6e 6f 76 61 32 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 47 65 74 4d 61 63 72 6f 52 65 67 49 64 28 22 66 6e 41 6e 6f 76 61 32 22 29 2c 20 69 6e 70 72 6e 67 2c 20 6f 75 74 72 6e 67 2c 20 73 61 6d 70 6c 65 5f 72 6f 77 73 2c 20 61 6c 70 68 61 29 } //2 xAnova2 = Application.Run(GetMacroRegId("fnAnova2"), inprng, outrng, sample_rows, alpha)
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_228{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {49 66 20 41 63 74 69 76 65 43 65 6c 6c 2e 56 61 6c 75 65 20 3d 20 22 43 6f 6d 70 61 6e 79 20 43 6f 64 65 22 } //1 If ActiveCell.Value = "Company Code"
		$a_00_1 = {63 6f 6c 4f 72 64 72 20 3d 20 41 72 72 61 79 28 22 44 69 76 69 73 69 6f 6e 22 2c 20 22 50 52 44 2e 48 69 65 72 35 20 44 65 73 63 22 2c 20 22 4d 61 74 65 72 69 61 6c 20 4e 6f 22 2c 20 22 4d 61 74 65 72 69 61 6c 20 44 65 73 63 72 69 70 74 69 6f 6e 22 2c 20 22 51 74 79 20 41 76 61 69 6c 61 62 6c 65 22 2c 20 22 43 6f 6d 70 61 6e 79 20 43 6f 64 65 22 2c 20 22 50 6c 61 6e 74 22 29 } //1 colOrdr = Array("Division", "PRD.Hier5 Desc", "Material No", "Material Description", "Qty Available", "Company Code", "Plant")
		$a_00_2 = {53 65 74 20 77 72 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 53 74 6f 63 6b 4c 69 73 74 22 29 2e 52 61 6e 67 65 28 22 43 37 22 29 29 } //1 Set wr = Workbooks.Open(ThisWorkbook.Sheets("StockList").Range("C7"))
		$a_00_3 = {41 63 74 69 76 65 43 65 6c 6c 2e 56 61 6c 75 65 20 3d 20 22 4d 61 74 65 72 69 61 6c 20 44 65 73 63 72 69 70 74 69 6f 6e 22 } //1 ActiveCell.Value = "Material Description"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_229{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6f 45 6e 76 2e 53 61 76 65 56 61 72 69 61 62 6c 65 20 22 6d 5f 4f 41 54 61 62 6c 65 4a 6f 69 6e 51 75 65 72 79 22 2c 20 6d 5f 4f 41 54 61 62 6c 65 4a 6f 69 6e 51 75 65 72 79 } //1 oEnv.SaveVariable "m_OATableJoinQuery", m_OATableJoinQuery
		$a_00_1 = {6f 45 6e 76 2e 53 61 76 65 56 61 72 69 61 62 6c 65 20 22 6d 5f 4f 41 54 61 62 6c 65 4e 61 6d 65 22 2c 20 6d 5f 4f 41 54 61 62 6c 65 4e 61 6d 65 } //1 oEnv.SaveVariable "m_OATableName", m_OATableName
		$a_00_2 = {43 61 6c 6c 20 4d 73 67 42 6f 78 28 22 4f 41 20 52 65 70 6f 72 74 73 20 63 6f 75 6c 64 20 6e 6f 74 20 66 69 6e 64 20 6e 61 6d 65 64 20 72 61 6e 67 65 20 27 22 20 26 20 73 52 61 6e 67 65 4e 61 6d 65 20 26 20 22 27 2e 22 2c 20 76 62 4f 4b 4f 6e 6c 79 20 2b 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e 2c 20 22 4f 41 20 52 65 70 6f 72 74 73 22 29 } //1 Call MsgBox("OA Reports could not find named range '" & sRangeName & "'.", vbOKOnly + vbExclamation, "OA Reports")
		$a_00_3 = {49 66 20 4c 65 66 74 28 2e 45 72 72 6f 72 54 69 74 6c 65 2c 20 4c 65 6e 28 22 4f 41 20 45 64 69 74 6f 72 22 29 29 20 3d 20 22 4f 41 20 45 64 69 74 6f 72 22 20 54 68 65 6e } //1 If Left(.ErrorTitle, Len("OA Editor")) = "OA Editor" Then
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_230{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 43 44 58 4c 41 64 64 49 6e 50 72 6f 67 49 44 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 43 68 65 6d 44 72 61 77 45 78 63 65 6c 41 64 64 49 6e 31 39 2e 45 78 63 65 6c 41 64 64 49 6e 22 } //1 Private Const CDXLAddInProgID As String = "ChemDrawExcelAddIn19.ExcelAddIn"
		$a_00_1 = {43 53 42 52 2d 31 31 39 30 31 30 3a 20 52 75 6e 20 6d 65 74 68 6f 64 20 72 65 74 75 72 6e 20 6e 75 6c 6c 20 69 6e 20 63 68 65 6d 64 72 61 77 65 78 63 65 6c } //1 CSBR-119010: Run method return null in chemdrawexcel
		$a_00_2 = {43 53 42 52 2d 31 32 38 35 33 34 3a 20 53 61 76 65 64 20 77 6f 72 6b 73 68 65 65 74 20 69 73 20 6e 6f 74 20 72 65 63 6f 67 6e 69 7a 65 64 20 61 73 20 61 20 43 68 65 6d 4f 66 66 69 63 65 20 77 6f 72 6b 73 68 65 65 74 20 77 68 65 6e 20 72 65 6f 70 65 6e 20 69 74 } //1 CSBR-128534: Saved worksheet is not recognized as a ChemOffice worksheet when reopen it
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 43 53 58 4c 5f 4d 61 6b 65 4e 65 77 43 53 57 6f 72 6b 73 68 65 65 74 28 42 79 52 65 66 20 62 4d 61 64 65 53 68 65 65 74 20 41 73 20 42 6f 6f 6c 65 61 6e 29 } //1 Public Sub CSXL_MakeNewCSWorksheet(ByRef bMadeSheet As Boolean)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_231{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_00_0 = {42 6c 6f 6f 6d 62 65 72 67 55 49 2e 78 6c 61 } //1 BloombergUI.xla
		$a_00_1 = {42 42 50 54 5f 6d 6f 64 55 74 69 6c 69 74 79 5f 58 4c 2e 62 61 73 } //1 BBPT_modUtility_XL.bas
		$a_00_2 = {62 61 74 42 6c 6f 6f 6d 62 65 72 67 41 75 74 6f 43 6f 6c 6f 72 54 79 70 65 } //1 batBloombergAutoColorType
		$a_00_3 = {42 6c 6f 6f 6d 62 65 72 67 5c 4f 66 66 69 63 65 20 54 6f 6f 6c 73 5c 50 6f 77 65 72 54 6f 6f 6c 73 } //1 Bloomberg\Office Tools\PowerTools
		$a_00_4 = {67 41 64 64 69 6e 4c 6f 61 64 65 72 2e 4c 6f 61 64 4c 6f 63 61 6c 6c 79 20 22 42 6c 6f 6f 6d 62 65 72 67 55 49 50 50 54 4d 61 73 74 65 72 2e 70 70 61 22 } //1 gAddinLoader.LoadLocally "BloombergUIPPTMaster.ppa"
		$a_00_5 = {42 6c 6f 6f 6d 62 65 72 67 20 41 50 49 20 2d 20 54 6f 6f 6c 73 50 72 6f 78 79 } //1 Bloomberg API - ToolsProxy
		$a_00_6 = {61 64 64 69 6e 50 61 74 68 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 64 64 49 6e 73 28 22 42 6c 6f 6f 6d 62 65 72 67 55 49 50 50 54 22 29 2e 70 61 74 68 20 26 20 22 5c 22 20 26 20 61 64 64 69 6e 4e 61 6d 65 } //1 addinPath = Application.AddIns("BloombergUIPPT").path & "\" & addinName
		$a_00_7 = {42 6c 6f 6f 6d 62 65 72 67 20 50 6f 77 65 72 54 6f 6f 6c 73 } //1 Bloomberg PowerTools
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_232{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 64 72 69 76 65 72 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 65 6c 65 6e 69 75 6d 2e 45 64 67 65 44 72 69 76 65 72 22 29 } //1 Set driver = CreateObject("Selenium.EdgeDriver")
		$a_00_1 = {64 72 69 76 65 72 2e 47 65 74 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 74 75 74 6f 72 69 61 6c 73 70 6f 69 6e 74 2e 63 6f 6d 2f 69 6e 64 65 78 2e 68 74 6d 22 } //1 driver.Get "https://www.tutorialspoint.com/index.htm"
		$a_00_2 = {50 72 69 76 61 74 65 20 44 72 69 76 65 72 20 41 73 20 53 65 6c 65 6e 69 75 6d 2e 45 64 67 65 44 72 69 76 65 72 } //1 Private Driver As Selenium.EdgeDriver
		$a_00_3 = {72 69 76 65 72 2e 46 69 6e 64 45 6c 65 6d 65 6e 74 42 79 49 64 28 22 44 72 6f 70 44 6f 77 6e 4c 69 73 74 4d 53 46 69 73 63 61 6c 59 65 61 72 22 29 2e 53 65 6e 64 4b 65 79 73 20 43 65 6c 6c 73 28 72 2c 20 33 29 2e 56 61 6c 75 65 } //1 river.FindElementById("DropDownListMSFiscalYear").SendKeys Cells(r, 3).Value
		$a_00_4 = {46 75 6e 63 74 69 6f 6e 20 53 70 6c 69 74 39 37 28 73 53 74 72 20 41 73 20 56 61 72 69 61 6e 74 2c 20 73 64 65 6c 69 6d 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 56 61 72 69 61 6e 74 } //1 Function Split97(sStr As Variant, sdelim As String) As Variant
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}
rule _#ASRWin32ApiMacroExclusion_233{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 61 74 68 5f 64 62 20 3d 20 22 4d 3a 5c 53 69 74 65 73 5c 42 72 61 69 6e 65 5c 47 54 53 4f 5c 47 50 44 49 5c 43 43 50 44 5c 41 6e 61 6c 79 74 69 63 73 5c 44 42 20 50 51 41 5c 44 61 74 61 42 61 73 65 20 55 50 53 20 56 31 2e 30 5f 62 65 2e 61 63 63 64 62 22 } //1 path_db = "M:\Sites\Braine\GTSO\GPDI\CCPD\Analytics\DB PQA\DataBase UPS V1.0_be.accdb"
		$a_00_1 = {49 66 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 41 63 74 69 76 65 53 68 65 65 74 2e 42 6f 75 74 6f 6e 5f 62 72 61 69 6e 65 2e 56 61 6c 75 65 20 3d 20 54 72 75 65 20 54 68 65 6e 20 73 69 74 65 20 3d 20 22 42 52 41 5f 55 50 53 5f 54 32 22 } //1 If ThisWorkbook.ActiveSheet.Bouton_braine.Value = True Then site = "BRA_UPS_T2"
		$a_00_2 = {49 66 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 41 63 74 69 76 65 53 68 65 65 74 2e 42 6f 75 74 6f 6e 5f 73 6c 6f 75 67 68 2e 56 61 6c 75 65 20 3d 20 54 72 75 65 20 54 68 65 6e 20 73 69 74 65 20 3d 20 22 53 4c 48 5f 55 50 53 5f 41 4a 41 58 22 } //1 If ThisWorkbook.ActiveSheet.Bouton_slough.Value = True Then site = "SLH_UPS_AJAX"
		$a_00_3 = {53 71 6c 20 3d 20 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 30 35 5f 55 50 53 5f 43 72 65 77 20 22 } //1 Sql = "SELECT * FROM 05_UPS_Crew "
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_234{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {49 66 20 28 53 68 74 4e 61 6d 65 20 3d 20 22 44 42 22 29 20 4f 72 20 28 53 68 74 4e 61 6d 65 20 3d 20 22 54 49 54 4c 45 22 29 20 4f 72 20 28 53 68 74 4e 61 6d 65 20 3d } //1 If (ShtName = "DB") Or (ShtName = "TITLE") Or (ShtName =
		$a_00_1 = {4d 79 43 6c 6e 20 3d 20 72 31 2e 46 69 6e 64 28 6d 6f 6a 69 2c 20 4c 6f 6f 6b 41 74 3a 3d 78 6c 57 68 6f 6c 65 2c 20 4d 61 74 63 68 43 61 73 65 3a 3d 54 72 75 65 29 2e 43 6f 6c 75 6d 6e } //1 MyCln = r1.Find(moji, LookAt:=xlWhole, MatchCase:=True).Column
		$a_00_2 = {43 61 6c 6c 20 57 6f 72 6b 73 68 65 65 74 5f 53 65 74 74 69 6e 67 28 73 68 74 31 2c 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 4e 61 6d 65 2c 20 44 42 73 68 74 4e 61 6d 65 29 3a 20 49 66 20 73 68 74 31 20 49 73 20 4e 6f 74 68 69 6e 67 20 54 68 65 6e 20 45 78 69 74 20 53 75 62 } //1 Call Worksheet_Setting(sht1, ThisWorkbook.Name, DBshtName): If sht1 Is Nothing Then Exit Sub
		$a_00_3 = {44 69 6d 20 73 68 74 31 20 41 73 20 45 78 63 65 6c 2e 57 6f 72 6b 73 68 65 65 74 3a 20 53 65 74 20 73 68 74 31 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 4f 55 54 73 68 65 65 74 29 } //1 Dim sht1 As Excel.Worksheet: Set sht1 = ThisWorkbook.Worksheets(OUTsheet)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_235{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {49 46 28 43 4f 55 4e 54 41 28 5b 40 49 44 5d 3a 5b 40 5b 49 73 20 74 68 65 20 63 61 70 69 74 61 6c 20 70 72 6f 6a 65 63 74 20 77 69 74 68 69 6e 20 6f 72 20 61 62 6f 76 65 20 61 70 70 72 6f 76 65 64 20 43 50 4c 3f 5d 5d 29 3c 3d 31 } //1 IF(COUNTA([@ID]:[@[Is the capital project within or above approved CPL?]])<=1
		$a_00_1 = {5b 40 5b 49 73 20 74 68 65 20 63 61 70 69 74 61 6c 20 70 72 6f 6a 65 63 74 20 69 6e 63 6c 75 64 65 64 20 69 6e 20 74 68 65 20 31 30 20 79 65 61 72 20 43 61 70 69 74 61 6c 20 49 6e 76 65 73 74 6d 65 6e 74 20 50 6c 61 6e 3f 20 2a 5d 5d } //1 [@[Is the capital project included in the 10 year Capital Investment Plan? *]]
		$a_00_2 = {5b 40 5b 50 75 62 6c 69 73 68 20 45 73 74 2e 20 45 78 70 2e 20 74 6f 20 33 30 2d 4a 75 6e 20 49 6e 64 69 63 61 74 6f 72 5d 5d } //1 [@[Publish Est. Exp. to 30-Jun Indicator]]
		$a_00_3 = {5b 40 5b 45 73 74 69 6d 61 74 65 64 20 54 6f 74 61 6c 20 43 6f 73 74 20 28 24 30 30 30 29 20 2a 5d 5d } //1 [@[Estimated Total Cost ($000) *]]
		$a_00_4 = {5b 40 5b 45 73 74 69 6d 61 74 65 64 20 46 69 6e 61 6e 63 69 61 6c 20 43 6f 6d 70 6c 65 74 69 6f 6e 20 4d 6f 6e 74 68 2f 59 65 61 72 20 2a 5d 5d } //1 [@[Estimated Financial Completion Month/Year *]]
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_236{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 41 70 69 50 72 65 66 69 78 4d 50 52 65 6c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 73 70 32 30 31 33 2e 6d 79 61 74 6f 73 2e 6e 65 74 2f 6f 72 67 2f 65 77 6c 2f 69 6e 74 70 72 6f 6a 2f 50 72 6f 6a 73 2f 4c 37 39 33 38 25 32 30 2d 25 32 30 4d 65 72 63 68 2f 5f 61 70 69 22 } //2 Const ApiPrefixMPRel = "https://sp2013.myatos.net/org/ewl/intproj/Projs/L7938%20-%20Merch/_api"
		$a_00_1 = {6d 65 74 68 6f 64 20 3d 20 22 47 45 54 22 3a 20 71 75 65 72 79 20 3d 20 22 2f 53 50 5f 54 65 6e 61 6e 74 53 65 74 74 69 6e 67 73 5f 43 75 72 72 65 6e 74 22 } //2 method = "GET": query = "/SP_TenantSettings_Current"
		$a_00_2 = {6d 65 74 68 6f 64 20 3d 20 22 47 45 54 22 3a 20 71 75 65 72 79 20 3d 20 22 2f 77 65 62 2f 47 65 74 46 6f 6c 64 65 72 42 79 53 65 72 76 65 72 52 65 6c 61 74 69 76 65 55 72 6c 28 27 2f 6f 72 67 61 6e 69 7a 61 74 69 6f 6e 2f 67 62 75 2f 46 77 6c 2f 65 77 6c 2f 63 6f 6f 2f 50 61 79 6d 65 6e 74 73 20 70 72 6f 64 75 63 74 73 2f 49 50 50 20 47 6f 76 65 72 6e 61 6e 63 65 2f 43 52 2d 50 52 4f 4a 45 43 54 53 2f 32 30 32 31 27 29 22 } //2 method = "GET": query = "/web/GetFolderByServerRelativeUrl('/organization/gbu/Fwl/ewl/coo/Payments products/IPP Governance/CR-PROJECTS/2021')"
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_237{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 50 4d 53 58 44 61 74 61 46 69 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 46 4f 44 4d 63 6f 6d 6d 4d 53 58 44 61 74 61 2e 78 6c 73 78 22 } //1 Public Const SPMSXDataFileName As String = "FODMcommMSXData.xlsx"
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 6d 79 43 4f 53 4d 49 43 6d 61 69 6e 55 52 4c 53 74 72 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 68 74 74 70 73 3a 2f 2f 63 6f 73 6d 69 63 2e 63 72 6d 2e 64 79 6e 61 6d 69 63 73 2e 63 6f 6d 22 } //1 Public Const myCOSMICmainURLStr As String = "https://cosmic.crm.dynamics.com"
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 6d 79 4d 53 58 6d 61 69 6e 55 52 4c 53 74 72 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 68 74 74 70 73 3a 2f 2f 6d 69 63 72 6f 73 6f 66 74 73 61 6c 65 73 2e 63 72 6d 2e 64 79 6e 61 6d 69 63 73 2e 63 6f 6d 22 } //1 Public Const myMSXmainURLStr As String = "https://microsoftsales.crm.dynamics.com"
		$a_00_3 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 6e 65 77 42 65 74 61 57 62 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 54 6f 6f 6c 4e 61 6d 65 20 26 20 22 28 62 65 74 61 29 2e 78 6c 73 6d } //1 Public Const newBetaWbName As String = ToolName & "(beta).xlsm
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_238{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 22 50 6c 65 61 73 65 20 70 6f 70 75 6c 61 74 65 20 43 44 45 53 20 4d 61 74 63 68 20 54 79 70 65 20 63 6f 6c 75 6d 6e 20 61 73 20 70 65 72 20 73 65 6c 65 63 74 69 6f 6e 20 6f 6e 20 53 74 61 72 74 20 48 65 72 65 20 74 61 62 2e 20 50 6c 65 61 73 65 20 63 68 65 63 6b 20 77 69 74 68 20 47 53 47 2f 53 4f 50 20 66 6f 72 20 61 6e 79 20 63 6c 61 72 69 66 69 63 61 74 69 6f 6e 22 } //1 MsgBox "Please populate CDES Match Type column as per selection on Start Here tab. Please check with GSG/SOP for any clarification"
		$a_00_1 = {53 68 65 65 74 73 28 22 46 59 31 37 4c 61 6e 67 6c 6f 63 22 29 2e 56 69 73 69 62 6c 65 20 3d 20 69 } //1 Sheets("FY17Langloc").Visible = i
		$a_00_2 = {4c 6f 63 61 6c 5f 4e 75 72 74 75 72 65 20 3d 20 53 68 65 65 74 73 28 22 4d 61 72 6b 65 74 6f 20 4c 4d 22 29 2e 52 61 6e 67 65 28 22 43 33 31 22 29 2e 56 61 6c 75 65 } //1 Local_Nurture = Sheets("Marketo LM").Range("C31").Value
		$a_00_3 = {49 66 20 53 68 65 65 74 73 28 22 44 61 74 61 62 61 73 65 5f 44 61 74 61 22 29 2e 43 65 6c 6c 73 28 31 2c 20 69 29 2e 56 61 6c 75 65 20 3d 20 22 4c 65 61 64 4d 61 74 63 68 53 6f 75 72 63 65 4e 61 6d 65 22 20 54 68 65 6e } //1 If Sheets("Database_Data").Cells(1, i).Value = "LeadMatchSourceName" Then
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_239{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 46 4f 72 69 20 3d 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 43 65 6c 52 65 66 54 4d 50 22 29 } //2 Set FOri = CelDeNomBase("CelRefTMP")
		$a_00_1 = {4e 6f 6d 46 75 6c 6c 4f 72 69 20 3d 20 46 4f 72 69 2e 50 61 72 65 6e 74 2e 4e 61 6d 65 } //2 NomFullOri = FOri.Parent.Name
		$a_00_2 = {53 65 74 20 62 20 3d 20 46 4f 72 69 2e 52 61 6e 67 65 28 46 4f 72 69 2e 43 65 6c 6c 73 28 50 72 69 46 69 6c 20 2d 20 31 2c 20 50 72 69 43 6f 6c 29 2c 20 46 4f 72 69 2e 43 65 6c 6c 73 28 50 72 69 46 69 6c 20 2d 20 31 2c 20 55 6c 74 43 6f 6c 29 29 } //2 Set b = FOri.Range(FOri.Cells(PriFil - 1, PriCol), FOri.Cells(PriFil - 1, UltCol))
		$a_00_3 = {53 65 74 20 46 44 65 73 20 3d 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 43 65 6c 52 65 66 52 65 73 22 29 } //2 Set FDes = CelDeNomBase("CelRefRes")
		$a_00_4 = {46 44 65 73 2e 50 61 72 65 6e 74 2e 43 65 6c 6c 73 2e 43 6c 65 61 72 43 6f 6e 74 65 6e 74 73 } //2 FDes.Parent.Cells.ClearContents
		$a_00_5 = {53 65 74 20 62 20 3d 20 46 44 65 73 2e 52 61 6e 67 65 28 46 44 65 73 2e 43 65 6c 6c 73 28 50 72 69 46 69 6c 2c 20 50 72 69 43 6f 6c 29 2c 20 46 44 65 73 2e 43 65 6c 6c 73 28 55 6c 74 46 69 6c 2c 20 55 6c 74 43 6f 6c 29 29 } //2 Set b = FDes.Range(FDes.Cells(PriFil, PriCol), FDes.Cells(UltFil, UltCol))
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2) >=8
 
}
rule _#ASRWin32ApiMacroExclusion_240{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {43 30 31 20 2d 20 53 70 65 63 69 66 79 20 74 68 65 20 66 69 6e 61 6e 63 69 61 6c 20 69 6e 73 74 69 74 75 74 69 6f 6e 20 61 73 20 69 74 20 73 68 6f 75 6c 64 20 61 70 70 65 61 72 20 6f 6e 20 74 68 65 20 53 4d 53 20 52 65 70 6f 72 74 73 } //1 C01 - Specify the financial institution as it should appear on the SMS Reports
		$a_00_1 = {43 31 33 20 2d 20 46 49 4e 41 4e 43 49 41 4c 20 54 52 41 4e 53 41 43 54 49 4f 4e 20 46 45 45 20 43 4f 4c 4c 45 43 54 49 4f 4e 20 2f 20 46 55 4e 44 53 20 44 49 53 42 55 52 53 45 4d 45 4e 54 } //1 C13 - FINANCIAL TRANSACTION FEE COLLECTION / FUNDS DISBURSEMENT
		$a_00_2 = {43 32 30 20 2d 20 56 45 52 53 49 4f 4e 20 32 2e 33 20 46 49 4e 41 4e 43 49 41 4c 20 54 52 41 4e 53 41 43 54 49 4f 4e 20 2f 20 46 45 45 20 52 45 43 4f 52 44 } //1 C20 - VERSION 2.3 FINANCIAL TRANSACTION / FEE RECORD
		$a_00_3 = {43 30 36 20 2d 20 41 43 51 55 49 52 45 52 20 41 44 4a 55 53 54 4d 45 4e 54 20 26 20 4d 45 52 43 48 41 4e 44 49 53 45 20 43 52 45 44 20 44 45 54 41 49 4c } //1 C06 - ACQUIRER ADJUSTMENT & MERCHANDISE CRED DETAIL
		$a_00_4 = {43 31 37 20 2d 20 41 44 4d 49 4e 49 53 54 52 41 54 49 56 45 20 4d 45 53 53 41 47 45 20 31 20 54 52 41 4e 53 41 43 54 49 4f 4e 20 52 45 43 4f 52 44 } //1 C17 - ADMINISTRATIVE MESSAGE 1 TRANSACTION RECORD
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_241{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 75 74 45 43 4c 50 53 2e 53 65 6e 64 4b 65 79 73 20 22 56 53 52 49 4e 49 56 41 53 41 22 20 26 20 22 6c 65 61 73 65 70 6c 61 6e 31 22 } //1 autECLPS.SendKeys "VSRINIVASA" & "leaseplan1"
		$a_00_1 = {53 75 62 20 53 65 74 45 6e 76 44 65 74 61 69 6c 73 28 45 6e 76 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 70 77 64 20 41 73 20 53 74 72 69 6e 67 2c 20 4f 70 74 69 6f 6e 61 6c 20 75 73 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 56 53 52 49 4e 49 56 41 53 41 22 29 } //1 Sub SetEnvDetails(EnvName As String, pwd As String, Optional usrName As String = "VSRINIVASA")
		$a_00_2 = {4e 6f 6c 73 45 6d 75 6c 61 74 6f 72 20 3d 20 22 58 3a 5c 55 73 65 72 73 5c 73 72 69 6e 65 5c 44 65 73 6b 74 6f 70 5c 50 43 35 32 35 30 20 45 6d 75 6c 61 74 6f 72 20 69 63 6f 6e 2d 22 20 26 20 45 6e 76 4e 6f 20 26 20 22 2d 62 6f 78 2e 57 53 22 } //1 NolsEmulator = "X:\Users\srine\Desktop\PC5250 Emulator icon-" & EnvNo & "-box.WS"
		$a_00_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 4c 61 75 6e 63 68 50 43 4f 4d 4d 53 65 73 73 69 6f 6e 28 50 72 6f 66 69 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 53 65 73 73 69 6f 6e 49 44 20 41 73 20 49 6e 74 65 67 65 72 29 } //1 Public Function LaunchPCOMMSession(ProfileName As String, SessionID As Integer)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_242{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 73 74 72 4c 6f 63 61 6c 44 6f 63 50 61 74 68 20 3d 20 73 74 72 44 6f 77 6e 6c 6f 61 64 50 61 74 68 20 26 20 22 44 41 54 41 54 45 4c 22 20 26 20 73 74 72 4c 6f 63 61 6c 44 6f 63 45 78 74 65 6e 73 69 6f 6e } //1 gstrLocalDocPath = strDownloadPath & "DATATEL" & strLocalDocExtension
		$a_00_1 = {67 73 74 72 4c 6f 63 61 6c 44 61 74 61 50 61 74 68 20 3d 20 73 74 72 44 6f 77 6e 6c 6f 61 64 50 61 74 68 20 26 20 22 44 41 54 41 54 45 4c 2e 54 58 54 22 } //1 gstrLocalDataPath = strDownloadPath & "DATATEL.TXT"
		$a_00_2 = {6d 65 74 68 6f 64 20 77 68 65 6e 20 74 68 65 20 64 6f 63 75 6d 65 6e 74 20 69 73 20 61 6c 72 65 61 64 79 20 73 61 76 65 64 20 69 73 20 74 68 61 74 20 69 74 20 6d 61 79 20 70 72 6f 64 75 63 65 20 61 6e 20 65 78 74 72 61 20 22 53 45 4c 45 43 54 20 46 52 4f 4d 20 44 41 54 41 54 45 4c 2e 54 58 54 22 } //1 method when the document is already saved is that it may produce an extra "SELECT FROM DATATEL.TXT"
		$a_00_3 = {49 20 68 61 76 65 20 70 61 73 74 65 64 20 74 68 65 20 63 6f 64 65 20 77 68 69 63 68 20 6d 6f 64 69 66 69 65 64 20 74 68 65 20 4f 44 43 20 74 6f 20 72 65 66 65 72 65 6e 63 65 20 74 68 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 44 41 54 41 54 45 4c 2e 54 58 54 } //1 I have pasted the code which modified the ODC to reference the downloaded DATATEL.TXT
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_243{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 73 75 63 68 65 28 44 61 74 65 6e 62 6c 61 74 74 20 41 73 20 53 74 72 69 6e 67 2c 20 53 70 61 6c 74 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub suche(Datenblatt As String, Spalte As String)
		$a_00_1 = {44 69 6d 20 4d 65 72 6b 6d 61 6c 63 6f 6c 75 6d 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 42 65 6d 65 72 6b 75 6e 67 31 63 6f 6c 75 6d 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 42 65 6d 65 72 6b 75 6e 67 32 63 6f 6c 75 6d 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 50 61 72 61 6d 65 74 65 72 72 6f 77 20 41 73 20 49 6e 74 65 67 65 72 } //1 Dim Merkmalcolumn As Integer, Bemerkung1column As Integer, Bemerkung2column As Integer, Parameterrow As Integer
		$a_00_2 = {49 66 20 76 61 72 69 61 62 6c 65 20 3d 20 22 43 46 32 5f 37 30 5f 5a 55 42 45 48 4f 45 52 5f 43 4f 4e 54 49 46 4f 52 4d 22 20 54 68 65 6e } //1 If variable = "CF2_70_ZUBEHOER_CONTIFORM" Then
		$a_00_3 = {50 75 62 6c 69 63 20 45 6e 64 77 65 72 74 31 31 6b 6f 6d 6d 69 73 73 69 6f 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 45 6e 64 77 65 72 74 31 32 6b 6f 6d 6d 69 73 73 69 6f 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 45 6e 64 77 65 72 74 31 33 6b 6f 6d 6d 69 73 73 69 6f 6e 20 41 73 20 49 6e 74 65 67 65 72 } //1 Public Endwert11kommission As Integer, Endwert12kommission As Integer, Endwert13kommission As Integer
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_244{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 28 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 46 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 5c 64 61 74 61 5c 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 73 74 61 74 69 63 2e 78 6c 73 78 22 29 } //1 Workbooks.Open ("\\brummer.se\bfs\BFS-Operations\Function sheet\data\function sheet static.xlsx")
		$a_00_1 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 73 74 61 74 69 63 2e 78 6c 73 78 22 29 2e 43 6c 6f 73 65 20 28 46 61 6c 73 65 } //1 Workbooks("function sheet static.xlsx").Close (False
		$a_00_2 = {70 61 74 68 20 3d 20 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 4d 4f 5c 46 75 6e 63 74 69 6f 6e 20 53 68 65 65 74 5c 41 72 63 68 69 76 65 22 } //1 path = "\\brummer.se\bfs\BFS-Operations\MO\Function Sheet\Archive"
		$a_00_3 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 28 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 5c 64 61 74 61 5c 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 64 61 74 61 20 50 50 2e 78 6c 73 78 22 29 } //1 Workbooks.Open ("\\brummer.se\bfs\BFS-Operations\function sheet\data\function sheet data PP.xlsx")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_245{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 22 50 6c 65 61 73 65 20 70 72 6f 76 69 64 65 20 74 68 65 20 72 65 71 75 69 72 65 64 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 2e 22 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 22 4f 72 64 65 72 20 6f 66 20 50 61 79 6d 65 6e 74 20 46 6f 72 6d 22 } //1 MsgBox "Please provide the required information.", vbCritical, "Order of Payment Form"
		$a_00_1 = {46 52 4d 4d 65 61 6c 73 42 72 2e 4c 42 4c 4d 65 61 6c 73 42 72 2e 43 61 70 74 69 6f 6e 20 3d 20 22 42 65 6c 6f 77 20 69 73 20 74 68 65 20 64 65 74 61 69 6c 65 64 20 62 72 65 61 6b 64 6f 77 6e 20 6f 66 20 79 6f 75 72 20 6d 65 61 6c 73 20 64 61 74 65 64 20 22 } //1 FRMMealsBr.LBLMealsBr.Caption = "Below is the detailed breakdown of your meals dated "
		$a_00_2 = {4d 73 67 42 6f 78 20 22 54 68 65 20 6d 6f 73 74 20 73 65 6e 69 6f 72 20 72 61 6e 6b 69 6e 67 20 70 65 72 73 6f 6e 6e 65 6c 20 63 61 6e 6e 6f 74 20 62 65 20 64 65 6c 65 74 65 64 21 22 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 22 4f 52 44 45 52 20 4f 46 20 50 41 59 4d 45 4e 54 22 } //1 MsgBox "The most senior ranking personnel cannot be deleted!", vbCritical, "ORDER OF PAYMENT"
		$a_00_3 = {43 61 73 65 20 22 35 36 38 35 35 37 35 33 20 45 6e 74 65 72 74 61 69 6e 6d 65 6e 74 2f 52 65 70 72 65 73 65 6e 74 61 74 69 6f 6e 20 28 77 69 74 68 20 63 75 73 74 6f 6d 65 72 73 2f 76 65 6e 64 6f 72 73 2f 6e 6f 6e 2d 63 65 6d 65 78 29 22 } //1 Case "56855753 Entertainment/Representation (with customers/vendors/non-cemex)"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_246{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 47 65 74 4f 53 45 41 70 70 6c 69 63 61 74 69 6f 6e 28 42 79 52 65 66 20 72 65 74 76 61 6c 20 41 73 20 41 73 70 65 6e 4f 53 45 57 6f 72 6b 62 6f 6f 6b 2e 4f 53 45 41 70 70 6c 69 63 61 74 69 6f 6e 29 } //10 Public Sub GetOSEApplication(ByRef retval As AspenOSEWorkbook.OSEApplication)
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 47 65 74 41 53 57 41 70 70 6c 69 63 61 74 69 6f 6e 28 42 79 52 65 66 20 72 65 74 76 61 6c 20 41 73 20 41 73 70 65 6e 4f 53 45 57 6f 72 6b 62 6f 6f 6b 2e 4f 53 45 41 70 70 6c 69 63 61 74 69 6f 6e 29 } //10 Public Sub GetASWApplication(ByRef retval As AspenOSEWorkbook.OSEApplication)
		$a_00_2 = {61 70 70 2e 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 20 28 22 41 73 70 65 6e 54 65 63 68 2e 41 53 57 58 4c 2e 43 6f 6d 6d 61 6e 64 73 2e 52 75 6e 43 6f 6d 6d 61 6e 64 22 29 } //1 app.ExecuteCommand ("AspenTech.ASWXL.Commands.RunCommand")
		$a_00_3 = {61 70 70 2e 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 20 28 22 41 73 70 65 6e 54 65 63 68 2e 41 53 57 58 4c 2e 43 6f 6d 6d 61 6e 64 73 2e 45 78 63 65 6c 32 4d 6f 64 65 6c 43 6f 6d 6d 61 6e 64 22 29 } //1 app.ExecuteCommand ("AspenTech.ASWXL.Commands.Excel2ModelCommand")
		$a_00_4 = {61 70 70 2e 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 20 28 22 41 73 70 65 6e 54 65 63 68 2e 41 53 57 58 4c 2e 43 6f 6d 6d 61 6e 64 73 2e 4c 6f 61 64 53 6e 61 70 73 68 6f 74 43 6f 6d 6d 61 6e 64 22 29 } //1 app.ExecuteCommand ("AspenTech.ASWXL.Commands.LoadSnapshotCommand")
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=13
 
}
rule _#ASRWin32ApiMacroExclusion_247{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 63 61 6c 63 75 6c 61 74 65 4e 65 77 47 72 6f 73 73 41 76 61 69 6c 61 62 69 6c 69 74 79 28 75 6e 61 76 61 69 6c 61 62 69 6c 69 74 79 44 69 63 74 69 6f 6e 61 72 79 20 41 73 20 44 69 63 74 69 6f 6e 61 72 79 2c 20 62 69 6e 6f 63 73 41 76 61 69 6c 61 62 69 6c 69 74 79 4d 6e 67 20 41 73 20 42 69 6e 6f 63 73 41 76 61 69 6c 61 62 69 6c 69 74 79 4d 61 6e 61 67 65 72 29 20 41 73 20 44 69 63 74 69 6f 6e 61 72 79 } //1 Public Function calculateNewGrossAvailability(unavailabilityDictionary As Dictionary, binocsAvailabilityMng As BinocsAvailabilityManager) As Dictionary
		$a_00_1 = {50 72 69 76 61 74 65 20 70 41 70 69 4d 61 6e 61 67 65 72 20 41 73 20 41 70 69 44 61 74 61 4d 61 6e 61 67 65 72 } //1 Private pApiManager As ApiDataManager
		$a_00_2 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 63 72 65 61 74 65 43 68 75 6e 6b 54 61 62 6c 65 52 65 6d 6f 76 65 44 61 74 65 73 41 6e 64 51 75 61 6e 74 69 74 79 46 6f 72 45 78 70 65 72 74 69 73 65 28 42 79 52 65 66 20 64 65 6d 61 6e 64 54 61 62 6c 65 20 41 73 20 54 61 62 6c 65 29 20 41 73 20 54 61 62 6c 65 } //1 Private Function createChunkTableRemoveDatesAndQuantityForExpertise(ByRef demandTable As Table) As Table
		$a_00_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 67 65 74 45 6d 70 6c 6f 79 65 65 57 6f 72 6b 52 65 67 69 6d 65 28 65 6d 70 6c 6f 79 65 65 43 6f 64 65 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 44 6f 75 62 6c 65 } //1 Public Function getEmployeeWorkRegime(employeeCode As String) As Double
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_248{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 28 22 56 45 48 49 43 4c 45 20 2f 20 54 52 41 49 4c 45 52 20 43 4f 55 4c 44 20 4e 4f 54 20 42 45 20 46 4f 55 4e 44 2e 20 50 4c 45 41 53 45 20 53 45 41 52 43 48 20 41 47 41 49 4e 2c 20 4f 52 20 45 4e 54 45 52 20 44 45 54 41 49 4c 53 20 4d 41 4e 55 41 4c 4c 59 2e 22 29 2c 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e 2c 20 22 50 4c 45 41 53 45 20 4e 4f 54 45 21 22 } //1 MsgBox ("VEHICLE / TRAILER COULD NOT BE FOUND. PLEASE SEARCH AGAIN, OR ENTER DETAILS MANUALLY."), vbExclamation, "PLEASE NOTE!"
		$a_00_1 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4f 43 54 20 28 46 29 22 29 2e 53 65 6c 65 63 74 } //1 ThisWorkbook.Sheets("OCT (F)").Select
		$a_00_2 = {49 66 20 53 68 69 70 2e 76 61 6c 75 65 20 3d 20 22 4d 53 4d 22 20 4f 72 20 53 68 69 70 2e 76 61 6c 75 65 20 3d 20 22 4e 4f 52 4d 41 4e 44 49 45 22 20 54 68 65 6e } //1 If Ship.value = "MSM" Or Ship.value = "NORMANDIE" Then
		$a_00_3 = {50 4c 45 41 53 45 20 43 4f 4d 50 4c 45 54 45 20 41 4c 4c 20 4d 41 4e 44 41 54 4f 52 59 20 42 4f 58 45 53 20 42 45 46 4f 52 45 20 43 4f 4e 54 49 4e 55 49 4e 47 2e 20 49 46 20 52 45 43 4f 52 44 49 4e 47 20 41 20 48 55 42 20 53 45 4c 45 43 54 49 4f 4e 2c 20 4d 41 4b 45 20 53 55 52 45 20 54 4f 20 43 4f 4e 44 55 43 54 20 41 20 53 45 41 52 43 48 20 46 4f 52 20 54 48 45 20 56 45 48 49 43 4c 45 20 2f 20 54 52 41 49 4c 45 52 20 52 45 47 20 46 49 52 53 54 } //1 PLEASE COMPLETE ALL MANDATORY BOXES BEFORE CONTINUING. IF RECORDING A HUB SELECTION, MAKE SURE TO CONDUCT A SEARCH FOR THE VEHICLE / TRAILER REG FIRST
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_249{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 73 73 65 6d 62 6c 61 2e 63 6f 6d 2f 73 70 61 63 65 73 2f 73 6b 61 62 65 6c 6f 6e 64 65 73 69 67 6e 2d 70 72 6f 64 75 63 74 69 6f 6e 74 65 61 6d 2f 77 69 6b 69 2f 47 65 6e 76 65 6a 73 74 61 73 74 65 72 5f 69 5f 57 6f 72 64 45 6e 67 69 6e 65 } //1 assembla.com/spaces/skabelondesign-productionteam/wiki/Genvejstaster_i_WordEngine
		$a_00_1 = {43 61 73 65 20 22 62 74 6e 57 61 76 65 31 22 2c 20 22 62 74 6e 57 61 76 65 32 22 2c 20 22 62 74 6e 57 61 76 65 33 22 2c 20 22 62 74 6e 57 61 76 65 34 22 2c 20 22 62 74 6e 57 61 76 65 35 22 2c 20 22 62 74 6e 50 69 63 74 75 72 65 53 6d 61 6c 6c 22 2c 20 22 62 74 6e 42 6f 74 74 6f 6d 42 6f 72 64 65 72 53 68 6f 77 22 2c 20 22 62 74 6e 42 6f 74 74 6f 6d 42 6f 72 64 65 72 48 69 64 65 22 } //1 Case "btnWave1", "btnWave2", "btnWave3", "btnWave4", "btnWave5", "btnPictureSmall", "btnBottomBorderShow", "btnBottomBorderHide"
		$a_00_2 = {4a 41 53 20 32 33 2f 31 31 2d 32 30 31 32 20 44 69 73 61 62 6c 65 64 20 61 6e 64 20 62 43 68 65 63 6b 42 6f 78 56 61 6c 75 65 20 72 65 74 75 72 6e 20 70 61 72 61 6d 65 74 65 72 20 61 64 64 65 64 } //1 JAS 23/11-2012 Disabled and bCheckBoxValue return parameter added
		$a_00_3 = {64 62 67 4e 6f 43 68 65 63 6b 70 6f 69 6e 74 73 20 3d 20 64 62 67 4c 6f 67 45 72 72 6f 72 20 4f 72 20 64 62 67 4c 6f 67 57 61 72 6e 69 6e 67 20 4f 72 20 64 62 67 4c 6f 67 49 6e 66 6f 72 6d 61 74 69 6f 6e 61 6c 20 4f 72 20 64 62 67 57 69 6e 64 6f 77 50 72 6f 63 20 4f 72 20 64 62 67 52 65 73 6f 75 72 63 65 73 } //1 dbgNoCheckpoints = dbgLogError Or dbgLogWarning Or dbgLogInformational Or dbgWindowProc Or dbgResources
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_250{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 45 6e 74 72 79 53 68 65 65 74 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 56 65 72 73 69 6f 6e 22 29 } //1 Set EntrySheet = ThisWorkbook.Worksheets("Version")
		$a_00_1 = {70 72 65 66 69 78 20 3d 20 22 49 4e 53 45 52 54 20 49 4e 54 4f 20 72 65 66 64 61 74 61 76 61 6c 75 65 68 69 65 72 61 72 63 68 79 20 28 70 61 72 65 6e 74 49 64 2c 20 63 68 69 6c 64 49 64 29 20 56 41 4c 55 45 53 22 } //1 prefix = "INSERT INTO refdatavaluehierarchy (parentId, childId) VALUES"
		$a_00_2 = {50 72 6f 64 75 63 65 48 65 61 64 65 72 20 66 69 6c 65 6e 61 6d 65 2c 20 22 45 78 74 65 72 6e 61 6c 53 79 73 74 65 6d 20 72 65 66 65 72 65 6e 63 65 20 64 61 74 61 20 73 63 72 69 70 74 22 2c 20 72 65 6c 65 61 73 65 } //1 ProduceHeader filename, "ExternalSystem reference data script", release
		$a_00_3 = {70 72 65 66 69 78 20 3d 20 22 49 4e 53 45 52 54 20 49 4e 54 4f 20 52 65 66 44 61 74 61 53 65 74 20 28 52 65 66 44 61 74 61 53 65 74 49 64 2c 20 52 65 66 44 61 74 61 53 65 74 4e 61 6d 65 2c 20 52 65 66 44 61 74 61 53 65 74 44 65 73 63 2c 20 53 68 6f 72 74 44 65 73 63 4c 65 6e 67 74 68 2c 20 49 6e 69 74 69 61 6c 44 61 74 61 46 69 6c 65 4e 61 6d 65 2c 20 43 72 65 61 74 65 64 55 73 65 72 49 64 2c 20 43 72 65 61 74 65 64 44 61 74 65 54 69 6d 65 2c 20 4c 61 73 74 55 70 64 61 74 65 64 55 73 65 72 49 64 2c 20 4c 61 73 74 55 70 64 61 74 65 64 44 61 74 65 54 69 6d 65 29 20 56 41 4c 55 45 53 22 } //1 prefix = "INSERT INTO RefDataSet (RefDataSetId, RefDataSetName, RefDataSetDesc, ShortDescLength, InitialDataFileName, CreatedUserId, CreatedDateTime, LastUpdatedUserId, LastUpdatedDateTime) VALUES"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_251{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 43 72 65 61 74 65 4e 65 77 44 6f 6f 72 28 42 79 56 61 6c 20 44 6f 6f 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 50 43 5f 63 6f 64 65 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 53 74 6f 72 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 41 66 74 65 72 42 79 53 68 65 65 74 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 } //1 Sub CreateNewDoor(ByVal DoorName As String, ByVal PC_code As String, ByVal StoreName As String, ByVal AfterBySheetName As String
		$a_00_1 = {53 75 62 20 4d 6f 76 65 41 66 74 65 72 28 42 79 56 61 6c 20 44 6f 6f 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 41 66 74 65 72 42 79 53 68 65 65 74 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub MoveAfter(ByVal DoorName As String, ByVal AfterBySheetName As String)
		$a_00_2 = {61 72 72 20 3d 20 41 72 72 61 79 28 22 41 72 63 27 54 65 72 79 78 22 2c 20 22 41 74 6f 6d 69 63 22 2c 20 22 50 50 22 2c 20 22 50 72 65 63 6f 72 22 2c 20 22 53 61 6c 48 47 22 2c 20 22 53 61 6c 6f 6d 6f 6e 22 2c 20 22 53 75 75 6e 74 6f 22 2c 20 22 57 69 6c 73 6f 6e 20 47 6f 6c 66 22 2c 20 22 57 69 6c 73 6f 6e 20 52 61 63 6b 65 74 22 2c 20 22 57 69 6c 73 6f 6e 20 53 47 22 2c 20 22 57 69 6c 73 6f 6e 20 54 45 41 4d 22 29 } //1 arr = Array("Arc'Teryx", "Atomic", "PP", "Precor", "SalHG", "Salomon", "Suunto", "Wilson Golf", "Wilson Racket", "Wilson SG", "Wilson TEAM")
		$a_00_3 = {43 61 6c 6c 20 72 65 67 69 6f 6e 43 6f 70 79 44 61 74 61 28 44 6f 6f 72 4e 61 6d 65 2c 20 22 45 31 36 22 2c 20 22 51 31 32 34 22 2c 20 22 45 31 33 22 2c 20 22 51 31 32 31 22 29 } //1 Call regionCopyData(DoorName, "E16", "Q124", "E13", "Q121")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_252{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 55 70 64 61 74 65 54 65 61 6d 4f 6e 54 65 61 6d 48 61 70 70 69 6e 65 73 73 53 68 65 65 74 28 73 68 20 41 73 20 45 78 63 65 6c 2e 57 6f 72 6b 73 68 65 65 74 2c 20 6c 6e 67 53 70 72 69 6e 74 4e 72 20 41 73 20 4c 6f 6e 67 2c 20 4f 70 74 69 6f 6e 61 6c 20 62 54 72 61 6e 73 66 65 72 20 41 73 20 42 6f 6f 6c 65 61 6e 20 3d 20 46 61 6c 73 65 29 } //1 Sub UpdateTeamOnTeamHappinessSheet(sh As Excel.Worksheet, lngSprintNr As Long, Optional bTransfer As Boolean = False)
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 56 65 72 77 69 6a 64 65 72 52 65 67 65 6c 55 69 74 53 70 72 69 6e 74 50 6c 61 6e 6e 69 6e 67 53 68 65 65 74 28 73 68 20 41 73 20 45 78 63 65 6c 2e 57 6f 72 6b 73 68 65 65 74 2c 20 69 52 6f 77 45 6d 70 6c 6f 79 65 65 20 41 73 20 4c 6f 6e 67 29 } //1 Private Sub VerwijderRegelUitSprintPlanningSheet(sh As Excel.Worksheet, iRowEmployee As Long)
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 43 6f 75 6e 74 53 70 72 69 6e 74 50 6c 61 6e 6e 69 6e 67 53 68 65 65 74 73 28 4f 70 74 69 6f 6e 61 6c 20 62 45 78 69 73 74 73 20 41 73 20 42 6f 6f 6c 65 61 6e 20 3d 20 54 72 75 65 29 20 41 73 20 4c 6f 6e 67 } //1 Function CountSprintPlanningSheets(Optional bExists As Boolean = True) As Long
		$a_00_3 = {44 69 6d 20 50 72 65 73 65 6e 74 5f 68 6f 75 72 73 2c 20 41 76 61 69 6c 61 62 69 6c 69 74 79 2c 20 41 76 61 69 6c 61 62 6c 65 5f 68 6f 75 72 73 2c 20 50 72 6f 64 75 63 74 69 76 69 74 79 2c 20 50 6c 61 6e 6e 61 62 6c 65 5f 68 6f 75 72 73 2c 20 53 50 50 48 2c 20 50 6c 61 6e 6e 61 62 6c 65 5f 73 74 6f 72 79 70 6f 69 6e 74 73 20 41 73 20 44 6f 75 62 6c 65 } //1 Dim Present_hours, Availability, Available_hours, Productivity, Plannable_hours, SPPH, Plannable_storypoints As Double
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_253{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 74 72 53 6f 75 72 63 65 46 69 6c 65 20 3d 20 22 5c 5c 70 6f 69 73 65 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 6c 6f 63 61 6c 5c 44 61 74 61 5c 49 4e 44 5c 53 68 61 72 65 64 5c 54 72 61 6e 73 66 65 72 5c 41 41 20 44 65 76 5c 42 4e 4f 5c 4c 41 4c 5f 53 65 61 72 63 68 5f 42 45 2e 78 6c 73 78 22 } //1 strSourceFile = "\\poise.homeoffice.local\Data\IND\Shared\Transfer\AA Dev\BNO\LAL_Search_BE.xlsx"
		$a_00_1 = {4d 73 67 42 6f 78 20 22 4e 6f 20 72 65 73 75 6c 74 73 20 66 6f 75 6e 64 2e 20 50 6c 65 61 73 65 20 63 68 65 63 6b 20 79 6f 75 72 20 63 72 69 74 65 72 69 61 20 61 6e 64 20 74 72 79 20 61 67 61 69 6e 2e 22 2c 20 76 62 49 6e 66 6f 72 6d 61 74 69 6f 6e 2c 20 22 4c 41 4c 20 53 65 61 72 63 68 20 54 6f 6f 6c 22 } //1 MsgBox "No results found. Please check your criteria and try again.", vbInformation, "LAL Search Tool"
		$a_00_2 = {4d 73 67 42 6f 78 20 22 52 65 73 75 6c 74 73 20 63 6f 6e 74 61 69 6e 20 6d 6f 72 65 20 74 68 61 6e 20 32 35 30 30 20 72 65 63 6f 72 64 73 2e 20 50 6c 65 61 73 65 20 72 65 66 69 6e 65 20 79 6f 75 72 20 73 65 61 72 63 68 20 63 72 69 74 65 72 69 61 20 61 6e 64 20 74 72 79 20 61 67 61 69 6e 2e 22 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 22 4c 41 4c 20 53 65 61 72 63 68 20 54 6f 6f 6c 22 } //1 MsgBox "Results contain more than 2500 records. Please refine your search criteria and try again.", vbCritical, "LAL Search Tool"
		$a_00_3 = {73 74 72 50 61 74 68 20 3d 20 22 5c 5c 70 6f 69 73 65 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 6c 6f 63 61 6c 5c 44 61 74 61 5c 49 4e 44 5c 53 68 61 72 65 64 5c 54 72 61 6e 73 66 65 72 5c 41 41 20 44 65 76 5c 42 4e 4f 5c 53 65 61 72 63 68 5f 41 75 64 69 74 5f 42 45 2e 61 63 63 64 62 22 } //1 strPath = "\\poise.homeoffice.local\Data\IND\Shared\Transfer\AA Dev\BNO\Search_Audit_BE.accdb"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule _#ASRWin32ApiMacroExclusion_254{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {74 68 69 73 20 6d 6f 64 75 6c 65 20 73 65 6e 64 73 20 61 20 6a 71 6c 20 71 75 65 72 79 20 74 6f 20 6a 69 72 61 20 75 73 69 6e 67 20 74 68 65 20 72 65 73 74 20 61 70 69 20 61 6e 64 20 74 68 65 6e 20 70 72 6f 63 65 73 73 65 73 20 74 68 65 20 6a 73 6f 6e 20 72 65 73 70 6f 6e 73 65 } //3 this module sends a jql query to jira using the rest api and then processes the json response
		$a_00_1 = {75 70 64 61 74 69 6e 67 20 74 68 65 20 72 6f 77 73 20 61 6e 64 20 63 6f 6c 75 6d 6e 73 20 69 6e 20 74 68 65 20 6a 69 72 61 20 65 78 74 72 61 63 74 20 74 61 62 6c 65 20 77 69 74 68 20 74 68 65 20 64 61 74 61 20 74 68 61 74 20 69 73 20 72 65 74 75 72 6e 65 64 } //3 updating the rows and columns in the jira extract table with the data that is returned
		$a_00_2 = {62 79 20 63 2e 20 72 6f 73 73 20 6d 63 6b 65 6e 72 69 63 6b 20 28 6d 63 6b 65 6e 63 72 40 63 6f 6e 73 75 6c 74 61 6e 74 65 6d 61 69 6c 2e 63 6f 6d 2c 20 72 6d 63 6b 65 6e 72 69 63 6b 40 73 61 70 69 65 6e 74 2e 63 6f 6d 29 } //3 by c. ross mckenrick (mckencr@consultantemail.com, rmckenrick@sapient.com)
		$a_00_3 = {70 72 69 6f 72 20 74 6f 20 64 69 73 70 6c 61 79 69 6e 67 20 74 68 65 20 66 6f 72 6d 2c 20 70 6f 73 69 74 69 6f 6e 20 69 74 20 69 6e 20 74 68 65 20 6d 69 64 64 6c 65 20 6f 66 20 74 68 65 20 6a 69 72 61 20 65 78 74 72 61 63 74 20 73 68 65 65 74 20 77 69 6e 64 6f 77 } //3 prior to displaying the form, position it in the middle of the jira extract sheet window
		$a_00_4 = {72 65 66 72 65 73 68 6a 69 72 61 65 78 74 72 61 63 74 } //2 refreshjiraextract
		$a_00_5 = {6a 69 72 61 63 72 65 64 65 6e 74 69 61 6c 73 66 6f 72 6d } //2 jiracredentialsform
		$a_00_6 = {61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 65 72 72 6f 72 20 6c 6f 67 67 69 6e 67 20 6f 6e 20 74 6f 20 6a 69 72 61 } //2 authentication error logging on to jira
		$a_00_7 = {61 75 74 68 6f 72 69 7a 61 74 69 6f 6e 20 65 72 72 6f 72 20 6c 6f 67 67 69 6e 67 20 6f 6e 20 74 6f 20 6a 69 72 61 } //2 authorization error logging on to jira
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_255{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 18 00 00 "
		
	strings :
		$a_00_0 = {6f 72 61 63 6c 65 20 68 79 70 65 72 69 6f 6e 20 73 6d 61 72 74 20 76 69 65 77 20 66 6f 72 20 6f 66 66 69 63 65 } //2 oracle hyperion smart view for office
		$a_00_1 = {73 6d 61 72 74 76 69 65 77 5c 62 69 6e 5c 68 73 74 62 61 72 2e 78 6c 61 } //2 smartview\bin\hstbar.xla
		$a_00_2 = {68 73 74 62 61 72 73 6d 61 72 74 76 69 65 77 70 61 6e 65 6c } //1 hstbarsmartviewpanel
		$a_00_3 = {68 73 74 62 61 72 61 63 74 69 6f 6e } //1 hstbaraction
		$a_00_4 = {68 73 74 62 61 72 7a 6f 6f 6d 69 6e } //1 hstbarzoomin
		$a_00_5 = {68 73 74 62 61 72 7a 6f 6f 6d 6f 75 74 } //1 hstbarzoomout
		$a_00_6 = {68 73 74 62 61 72 70 69 76 6f 74 } //1 hstbarpivot
		$a_00_7 = {68 73 74 62 61 72 6b 65 65 70 6f 6e 6c 79 } //1 hstbarkeeponly
		$a_00_8 = {68 73 74 62 61 72 72 65 6d 6f 76 65 6f 6e 6c 79 } //1 hstbarremoveonly
		$a_00_9 = {68 73 74 62 61 72 72 65 66 72 65 73 68 } //1 hstbarrefresh
		$a_00_10 = {68 73 74 62 61 72 73 75 62 6d 69 74 64 61 74 61 } //1 hstbarsubmitdata
		$a_00_11 = {68 73 74 62 61 72 75 6e 64 6f } //1 hstbarundo
		$a_00_12 = {68 73 74 62 61 72 72 65 64 6f } //1 hstbarredo
		$a_00_13 = {68 73 74 62 61 72 63 6f 70 79 64 61 74 61 70 6f 69 6e 74 73 } //1 hstbarcopydatapoints
		$a_00_14 = {68 73 74 62 61 72 70 61 73 74 65 64 61 74 61 70 6f 69 6e 74 73 } //1 hstbarpastedatapoints
		$a_00_15 = {68 73 74 62 61 72 62 69 65 64 69 74 } //1 hstbarbiedit
		$a_00_16 = {68 73 74 62 61 72 70 6f 76 6d 61 6e 61 67 65 72 } //1 hstbarpovmanager
		$a_00_17 = {68 73 74 62 61 72 6d 65 6d 62 65 72 73 65 6c 65 63 74 69 6f 6e } //1 hstbarmemberselection
		$a_00_18 = {68 73 74 62 61 72 66 75 6e 63 74 69 6f 6e 62 75 69 6c 64 65 72 } //1 hstbarfunctionbuilder
		$a_00_19 = {68 73 74 62 61 72 61 64 6a 75 73 74 } //1 hstbaradjust
		$a_00_20 = {68 73 74 62 61 72 63 65 6c 6c 63 6f 6d 6d 65 6e 74 73 } //1 hstbarcellcomments
		$a_00_21 = {68 73 74 62 61 72 73 75 70 70 6f 72 74 69 6e 67 64 65 74 61 69 6c 73 } //1 hstbarsupportingdetails
		$a_00_22 = {68 73 74 62 61 72 74 61 6b 65 6f 66 66 6c 69 6e 65 } //1 hstbartakeoffline
		$a_00_23 = {68 73 74 62 61 72 72 65 66 72 65 73 68 6f 66 66 6c 69 6e 65 64 65 66 69 6e 69 74 69 6f 6e } //1 hstbarrefreshofflinedefinition
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*1+(#a_00_16  & 1)*1+(#a_00_17  & 1)*1+(#a_00_18  & 1)*1+(#a_00_19  & 1)*1+(#a_00_20  & 1)*1+(#a_00_21  & 1)*1+(#a_00_22  & 1)*1+(#a_00_23  & 1)*1) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_256{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {49 66 20 4c 73 74 41 63 74 73 50 69 63 6b 65 64 2e 4c 69 73 74 28 6c 69 73 74 5f 69 74 65 6d 29 20 3d 20 22 2a 2a 49 4e 41 50 50 52 4f 50 52 49 41 54 45 20 43 41 4c 4c 2a 2a 22 20 54 68 65 6e } //1 If LstActsPicked.List(list_item) = "**INAPPROPRIATE CALL**" Then
		$a_00_1 = {4d 73 67 42 6f 78 20 22 59 6f 75 20 6d 75 73 74 20 73 65 6c 65 63 74 20 27 33 3a 57 68 61 74 20 69 73 20 74 68 65 20 6d 61 69 6e 20 41 43 54 49 4f 4e 20 74 79 70 65 3f 27 22 } //1 MsgBox "You must select '3:What is the main ACTION type?'"
		$a_00_2 = {4d 73 67 42 6f 78 20 22 59 6f 75 20 6d 75 73 74 20 73 65 6c 65 63 74 20 27 37 3a 44 6f 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 46 4f 52 57 41 52 44 20 6f 72 20 72 65 66 65 72 20 74 68 69 73 20 72 65 71 75 65 73 74 20 6f 6e 77 61 72 64 73 3f 27 22 } //1 MsgBox "You must select '7:Do you need to FORWARD or refer this request onwards?'"
		$a_00_3 = {77 73 5f 6f 75 74 2e 43 65 6c 6c 73 28 77 72 69 74 65 5f 72 6f 77 2c 20 35 29 2e 56 61 6c 75 65 20 3d 20 49 49 66 28 52 61 64 42 72 61 6e 63 68 59 65 73 2c 20 22 50 72 6f 63 65 73 73 69 6e 67 22 2c 20 28 49 49 66 28 52 61 64 42 72 61 6e 63 68 4e 6f 2c 20 22 51 75 65 72 79 22 2c 20 28 49 49 66 28 52 61 64 42 72 61 6e 63 68 4f 74 68 65 72 2c 20 22 43 68 65 63 6b 22 2c 20 28 49 49 66 28 52 61 64 42 72 61 6e 63 68 4f 74 68 65 72 31 2c 20 22 42 61 69 6c 20 45 6e 64 22 2c 20 22 4f 74 68 65 72 22 29 29 29 29 29 29 29 } //1 ws_out.Cells(write_row, 5).Value = IIf(RadBranchYes, "Processing", (IIf(RadBranchNo, "Query", (IIf(RadBranchOther, "Check", (IIf(RadBranchOther1, "Bail End", "Other")))))))
		$a_00_4 = {49 49 66 28 52 61 64 46 69 72 73 74 59 65 73 2c 20 22 43 72 6f 77 6e 20 43 6f 75 72 74 22 2c 20 28 49 49 66 28 52 61 64 46 69 72 73 74 4e 6f 2c 20 22 4d 61 67 69 73 74 72 61 74 65 73 2f 59 6f 75 74 68 22 2c 20 28 49 49 66 28 52 61 64 46 69 72 73 74 4f 74 68 65 72 2c 20 22 50 72 69 73 6f 6e 22 2c 20 28 49 49 66 28 52 61 64 46 69 72 73 74 4f 74 68 65 72 31 2c 20 22 45 4d 53 20 49 6e 74 65 72 6e 61 6c 22 2c 20 28 49 49 66 28 52 61 64 46 69 72 73 74 4f 74 68 65 72 32 2c 20 22 55 4b 42 41 22 2c 20 22 4f 74 68 65 72 22 29 29 29 29 29 29 29 29 29 } //1 IIf(RadFirstYes, "Crown Court", (IIf(RadFirstNo, "Magistrates/Youth", (IIf(RadFirstOther, "Prison", (IIf(RadFirstOther1, "EMS Internal", (IIf(RadFirstOther2, "UKBA", "Other")))))))))
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule _#ASRWin32ApiMacroExclusion_257{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 0b 00 00 "
		
	strings :
		$a_00_0 = {71 76 69 64 69 61 6e 2e 78 6c 61 6d } //2 qvidian.xlam
		$a_00_1 = {69 66 20 73 61 76 69 6e 67 20 61 20 71 76 69 64 69 61 6e 20 66 69 6c 65 2c 20 75 70 64 61 74 65 20 74 68 65 20 75 69 } //2 if saving a qvidian file, update the ui
		$a_00_2 = {6c 65 61 76 69 6e 67 20 65 61 72 6c 79 20 28 71 76 69 64 69 61 6e 2e 78 6c 61 20 6f 72 20 65 6d 62 65 64 64 65 64 29 } //2 leaving early (qvidian.xla or embedded)
		$a_00_3 = {61 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 77 69 74 68 6f 75 74 20 73 61 76 69 6e 67 20 63 68 61 6e 67 65 73 20 62 61 63 6b 20 74 6f 20 71 76 69 64 69 61 6e 3f } //2 are you sure you wish to cancel without saving changes back to qvidian?
		$a_00_4 = {73 61 76 65 20 73 70 72 65 61 64 73 68 65 65 74 20 62 61 63 6b 20 74 6f 20 74 68 65 20 71 76 69 64 69 61 6e 20 64 6f 63 75 6d 65 6e 74 } //2 save spreadsheet back to the qvidian document
		$a_00_5 = {70 6c 65 61 73 65 20 70 61 73 74 65 20 79 6f 75 72 20 63 6f 6e 74 65 6e 74 20 68 65 72 65 2c 20 74 68 65 6e 20 63 6c 69 63 6b 20 27 73 61 76 65 20 74 6f 20 71 76 69 64 69 61 6e 27 } //2 please paste your content here, then click 'save to qvidian'
		$a_00_6 = {71 76 69 64 69 61 6e 73 65 72 76 65 72 20 76 61 72 69 61 62 6c 65 20 75 73 65 64 20 66 6f 72 20 6d 61 6e 61 67 69 6e 67 20 73 65 72 76 65 72 20 73 70 65 63 69 66 69 63 20 75 73 65 72 20 63 72 65 64 65 6e 74 69 61 6c 73 } //2 qvidianserver variable used for managing server specific user credentials
		$a_00_7 = {70 6c 65 61 73 65 20 64 6f 77 6e 6c 6f 61 64 20 74 68 65 20 63 6f 72 72 65 63 74 20 61 64 64 2d 69 6e 73 20 62 65 66 6f 72 65 20 70 65 72 66 6f 72 6d 69 6e 67 20 61 6e 79 20 71 76 69 64 69 61 6e 20 6f 70 65 72 61 74 69 6f 6e 73 } //2 please download the correct add-ins before performing any qvidian operations
		$a_00_8 = {77 6f 72 6b 20 6f 75 74 20 69 66 20 74 68 65 20 66 69 6c 65 20 69 73 20 22 6f 6e 65 20 6f 66 20 6f 75 72 73 22 20 69 6e 20 74 65 72 6d 73 20 6f 66 20 6d 75 6c 74 69 2d 65 64 69 74 } //1 work out if the file is "one of ours" in terms of multi-edit
		$a_00_9 = {74 68 69 73 20 6c 69 74 74 6c 65 20 6e 61 73 74 79 20 68 61 63 6b 20 69 73 20 62 65 63 61 75 73 65 20 65 78 63 65 6c 20 69 73 20 66 69 72 69 6e 67 20 74 68 69 73 20 65 76 65 6e 74 20 77 69 74 68 20 61 20 62 61 64 20 77 6f 72 6b 62 6f 6f 6b } //1 this little nasty hack is because excel is firing this event with a bad workbook
		$a_00_10 = {74 68 65 20 6f 6e 6c 79 20 77 61 79 20 69 20 73 65 65 6d 20 74 6f 20 62 65 20 61 62 6c 65 20 74 6f 20 74 72 61 70 20 69 74 20 69 73 20 61 63 63 65 73 73 20 74 68 65 20 6e 61 6d 65 } //1 the only way i seem to be able to trap it is access the name
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*2+(#a_00_6  & 1)*2+(#a_00_7  & 1)*2+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1) >=6
 
}
rule _#ASRWin32ApiMacroExclusion_258{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 30 30 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 30 30 53 2e 78 6c 73 22 } //1 FileCopy mobjInfo.PathGkgMyParmFolder & "EGA1C00S.xls", mobjInfo.PathMyFolder & "EGA1C00S.xls"
		$a_00_1 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 31 30 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 31 30 53 2e 78 6c 73 22 } //1 FileCopy mobjInfo.PathGkgMyParmFolder & "EGA1C10S.xls", mobjInfo.PathMyFolder & "EGA1C10S.xls"
		$a_00_2 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 32 30 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 32 30 53 2e 78 6c 73 22 } //1 FileCopy mobjInfo.PathGkgMyParmFolder & "EGA1C20S.xls", mobjInfo.PathMyFolder & "EGA1C20S.xls"
		$a_00_3 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 33 30 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 33 30 53 2e 78 6c 73 22 } //1 FileCopy mobjInfo.PathGkgMyParmFolder & "EGA1C30S.xls", mobjInfo.PathMyFolder & "EGA1C30S.xls"
		$a_00_4 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 31 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 31 53 2e 78 6c 73 22 } //1 FileCopy mobjInfo.PathGkgMyParmFolder & "EGA1C41S.xls", mobjInfo.PathMyFolder & "EGA1C41S.xls"
		$a_00_5 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 32 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 32 53 2e 78 6c 73 22 } //1 FileCopy mobjInfo.PathGkgMyParmFolder & "EGA1C42S.xls", mobjInfo.PathMyFolder & "EGA1C42S.xls"
		$a_00_6 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 33 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 33 53 2e 78 6c 73 22 } //1 FileCopy mobjInfo.PathGkgMyParmFolder & "EGA1C43S.xls", mobjInfo.PathMyFolder & "EGA1C43S.xls"
		$a_00_7 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 34 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 34 53 2e 78 6c 73 22 } //1 FileCopy mobjInfo.PathGkgMyParmFolder & "EGA1C44S.xls", mobjInfo.PathMyFolder & "EGA1C44S.xls"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=8
 
}