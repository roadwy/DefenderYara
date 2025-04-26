
rule TrojanDownloader_O97M_Qakbot_NQTT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.NQTT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 53 68 65 65 74 35 22 29 2e 52 61 6e 67 65 28 22 49 31 39 22 29 20 3d 20 22 72 65 67 73 76 72 33 32 20 2d 73 69 6c 65 6e 74 20 2e 2e 5c 58 65 72 74 69 73 32 2e 64 6c 6c 22 } //1 Sheets("Sheet5").Range("I19") = "regsvr32 -silent ..\Xertis2.dll"
		$a_01_1 = {53 68 65 65 74 73 28 22 53 68 65 65 74 35 22 29 2e 52 61 6e 67 65 28 22 48 39 22 29 20 3d 20 44 72 65 7a 64 65 6e 20 26 20 22 52 45 47 49 53 54 45 52 28 49 39 2c 49 31 30 26 4a 31 30 2c 49 31 31 2c 49 31 32 2c 2c 31 2c 39 29 22 } //1 Sheets("Sheet5").Range("H9") = Drezden & "REGISTER(I9,I10&J10,I11,I12,,1,9)"
		$a_01_2 = {26 20 22 45 58 45 43 28 49 31 38 29 22 } //1 & "EXEC(I18)"
		$a_01_3 = {53 68 65 65 74 73 28 22 53 68 65 65 74 35 22 29 2e 52 61 6e 67 65 28 22 4b 31 38 22 29 20 3d 20 22 2e 64 61 74 22 } //1 Sheets("Sheet5").Range("K18") = ".dat"
		$a_01_4 = {2e 52 61 6e 67 65 28 22 48 32 36 22 29 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 34 2e 43 61 70 74 69 6f 6e } //1 .Range("H26") = UserForm1.Label4.Caption
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}