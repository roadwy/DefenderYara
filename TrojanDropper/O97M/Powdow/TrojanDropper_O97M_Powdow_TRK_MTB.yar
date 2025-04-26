
rule TrojanDropper_O97M_Powdow_TRK_MTB{
	meta:
		description = "TrojanDropper:O97M/Powdow.TRK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 43 6c 6f 73 65 54 68 65 6d 65 44 61 74 61 20 4c 69 62 20 22 75 78 74 68 65 6d 65 2e 64 6c 6c 22 20 28 42 79 56 61 6c 20 68 54 68 65 6d 65 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 4c 6f 6e 67 } //1 Private Declare Function CloseThemeData Lib "uxtheme.dll" (ByVal hTheme As Long) As Long
		$a_01_1 = {52 65 67 75 6c 61 72 45 78 70 72 65 73 73 69 6f 6e 73 2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 20 56 42 41 2e 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 45 78 63 65 6c 56 42 41 2e 76 62 73 22 } //1 RegularExpressions.CreateTextFile VBA.Environ("TEMP") & "\ExcelVBA.vbs"
		$a_01_2 = {53 65 74 20 70 20 3d 20 52 65 67 75 6c 61 72 45 78 70 72 65 73 73 69 6f 6e 73 2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 56 42 41 2e 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 45 78 63 65 6c 56 42 41 2e 76 62 73 22 2c 20 38 2c 20 31 29 } //1 Set p = RegularExpressions.OpenTextFile(VBA.Environ("TEMP") & "\ExcelVBA.vbs", 8, 1)
		$a_03_3 = {70 2e 57 72 69 74 65 4c 69 6e 65 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 90 0c 02 00 70 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 27 } //1
		$a_01_4 = {65 72 72 52 65 74 75 72 6e 20 3d 20 6f 62 6a 69 6e 73 74 61 6e 63 65 2e 43 72 65 61 74 65 28 22 65 78 70 6c 6f 72 65 72 2e 65 78 65 20 22 20 26 20 56 42 41 2e 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 20 26 20 22 5c 45 78 63 65 6c 56 42 41 2e 76 62 73 22 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 29 } //1 errReturn = objinstance.Create("explorer.exe " & VBA.Environ("TEMP") & "\ExcelVBA.vbs", Null, objConfig, intProcessID)
		$a_01_5 = {54 4d 50 70 61 74 68 46 4e 61 6d 65 20 3d 20 54 65 6d 70 50 61 74 68 4e 61 6d 65 20 2b 20 22 5c 7e 43 6f 6e 76 49 63 6f 6e 54 6f 42 6d 70 2e 74 6d 70 22 } //1 TMPpathFName = TempPathName + "\~ConvIconToBmp.tmp"
		$a_01_6 = {43 61 6c 6c 20 41 50 49 4c 69 6e 65 28 55 73 65 72 43 6f 6e 74 72 6f 6c 2e 53 63 61 6c 65 57 69 64 74 68 20 2d 20 6d 5f 62 74 6e 52 65 63 74 2e 52 69 67 68 74 20 2b 20 6d 5f 62 74 6e 52 65 63 74 2e 6c 65 66 74 20 2b 20 74 6d 70 43 31 2c 20 74 6d 70 43 33 20 2b 20 74 6d 70 43 32 2c } //1 Call APILine(UserControl.ScaleWidth - m_btnRect.Right + m_btnRect.left + tmpC1, tmpC3 + tmpC2,
		$a_01_7 = {2e 52 65 64 20 3d 20 56 61 6c 28 22 26 48 22 20 26 20 48 65 78 24 28 52 47 42 43 6f 6c 6f 72 2e 52 65 64 29 20 26 20 22 30 30 22 29 } //1 .Red = Val("&H" & Hex$(RGBColor.Red) & "00")
		$a_01_8 = {54 65 6d 70 50 61 74 68 4e 61 6d 65 20 3d 20 6c 65 66 74 24 28 73 74 72 54 65 6d 70 2c 20 49 6e 53 74 72 28 73 74 72 54 65 6d 70 2c 20 43 68 72 24 28 30 29 29 20 2d 20 31 29 } //1 TempPathName = left$(strTemp, InStr(strTemp, Chr$(0)) - 1)
		$a_01_9 = {3d 20 6f 62 6a 53 65 72 76 69 63 65 2e 47 65 74 28 43 68 72 24 28 38 37 29 20 26 20 43 68 72 24 28 31 30 35 29 20 26 20 43 68 72 24 28 31 31 30 29 20 26 20 43 68 72 24 28 35 31 29 20 26 20 43 68 72 24 28 35 30 29 20 26 20 43 68 72 24 28 39 35 29 20 26 20 43 68 72 24 28 38 30 29 20 5f } //1 = objService.Get(Chr$(87) & Chr$(105) & Chr$(110) & Chr$(51) & Chr$(50) & Chr$(95) & Chr$(80) _
		$a_01_10 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 56 65 72 73 69 6f 6e 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 53 43 6f 6d 62 6f 42 6f 78 20 31 2e 30 2e 33 20 42 79 20 48 41 43 4b 50 52 4f 20 54 4d 22 } //1 Private Const Version As String = "SComboBox 1.0.3 By HACKPRO TM"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}