
rule Ransom_Win32_Mytreex_A{
	meta:
		description = "Ransom:Win32/Mytreex.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 17 00 00 "
		
	strings :
		$a_80_0 = {41 44 4d 49 4e 5f 4e 4f 7c 49 4e 54 5f } //ADMIN_NO|INT_  1
		$a_80_1 = {41 44 4d 49 4e 5f 59 45 53 7c 49 4e 54 5f } //ADMIN_YES|INT_  1
		$a_80_2 = {43 49 50 5f 53 54 41 52 54 45 44 } //CIP_STARTED  1
		$a_80_3 = {4d 41 53 54 45 52 5f 53 54 41 52 54 45 44 } //MASTER_STARTED  1
		$a_80_4 = {42 72 6f 53 74 3a } //BroSt:  1
		$a_80_5 = {46 69 78 4c 6e 6b 3a } //FixLnk:  1
		$a_80_6 = {47 65 74 52 64 6d 3a } //GetRdm:  1
		$a_80_7 = {4d 63 70 79 3a } //Mcpy:  1
		$a_80_8 = {4d 54 63 68 3a } //MTch:  1
		$a_80_9 = {5b 4e 44 5f 53 54 41 52 54 5d } //[ND_START]  1
		$a_80_10 = {5b 4e 46 5f 45 4e 44 5d } //[NF_END]  1
		$a_80_11 = {22 25 54 45 4d 50 25 5c 5b 45 58 45 5f 4e 41 4d 45 5d 22 } //"%TEMP%\[EXE_NAME]"  1
		$a_80_12 = {22 5b 54 4f 5f 50 41 54 48 5d 22 20 5b 50 41 52 41 4d 53 5d } //"[TO_PATH]" [PARAMS]  1
		$a_80_13 = {5c 52 75 6e 22 20 2f 76 20 22 5b 48 54 41 5f 4e 41 4d 45 5d 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 66 20 2f 64 20 22 5c 22 5b 48 54 41 5f 50 41 54 48 5d 22 5c 22 } //\Run" /v "[HTA_NAME]" /t REG_SZ /f /d "\"[HTA_PATH]"\"  2
		$a_80_14 = {5c 53 68 65 6c 6c 20 49 63 6f 6e 73 22 20 2f 76 20 22 32 39 22 20 2f 74 20 52 45 47 5f 53 5a 20 2f 66 20 2f 64 20 22 5b 49 43 4f 5f 50 41 54 48 5d 2c 30 22 } //\Shell Icons" /v "29" /t REG_SZ /f /d "[ICO_PATH],0"  2
		$a_80_15 = {2b 68 20 22 5b 54 4f 5f 44 49 52 5d 22 } //+h "[TO_DIR]"  1
		$a_80_16 = {2b 68 20 22 5b 54 4f 5f 50 41 54 48 5d 22 } //+h "[TO_PATH]"  1
		$a_80_17 = {2d 72 20 2d 73 20 2d 68 20 22 5b 54 4f 5f 50 41 54 48 5d 22 } //-r -s -h "[TO_PATH]"  1
		$a_80_18 = {22 5b 46 49 4c 45 4e 41 4d 45 5d 22 20 2f 45 20 2f 47 20 25 55 53 45 52 4e 41 4d 45 25 3a 46 20 2f 43 } //"[FILENAME]" /E /G %USERNAME%:F /C  1
		$a_80_19 = {2f 66 20 2f 71 20 22 5b 54 4f 5f 50 41 54 48 5d 22 } ///f /q "[TO_PATH]"  1
		$a_80_20 = {22 5b 44 49 52 5f 4e 41 4d 45 5d 5c 5b 48 49 44 5f 4e 41 4d 45 5d 22 20 3e 20 22 25 54 45 4d 50 25 5c 5b 45 58 45 5f 4e 41 4d 45 5d 22 } //"[DIR_NAME]\[HID_NAME]" > "%TEMP%\[EXE_NAME]"  2
		$a_80_21 = {22 5b 46 52 4f 4d 5f 50 41 54 48 5d 22 20 3e 20 22 5b 54 4f 5f 50 41 54 48 5d 22 } //"[FROM_PATH]" > "[TO_PATH]"  2
		$a_03_22 = {83 f8 02 74 0a 83 f8 03 74 05 83 f8 04 75 ?? 8d 45 f4 8b d3 e8 ?? ?? ?? ?? 8d 45 f4 ba ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 55 f4 8b 06 8b 08 ff 51 3c 4b 83 fb 42 75 } //1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*2+(#a_80_14  & 1)*2+(#a_80_15  & 1)*1+(#a_80_16  & 1)*1+(#a_80_17  & 1)*1+(#a_80_18  & 1)*1+(#a_80_19  & 1)*1+(#a_80_20  & 1)*2+(#a_80_21  & 1)*2+(#a_03_22  & 1)*1) >=8
 
}