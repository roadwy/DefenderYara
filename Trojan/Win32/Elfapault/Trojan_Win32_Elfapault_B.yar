
rule Trojan_Win32_Elfapault_B{
	meta:
		description = "Trojan:Win32/Elfapault.B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 09 00 10 00 00 "
		
	strings :
		$a_00_0 = {6e 65 74 20 73 74 6f 70 20 73 68 61 72 65 64 61 63 63 65 73 73 } //1 net stop sharedaccess
		$a_00_1 = {69 6e 74 20 75 74 20 73 75 63 21 } //1 int ut suc!
		$a_02_2 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 6c 73 61 73 73 ?? 2e 65 78 65 } //1
		$a_00_3 = {53 65 6e 64 69 6e 67 20 70 61 79 6c 6f 61 64 32 2e 2e 2e 66 69 6e 69 73 68 } //1 Sending payload2...finish
		$a_00_4 = {34 62 33 32 34 66 63 38 2d 31 36 37 30 2d 30 31 64 33 2d 31 32 37 38 2d 35 61 34 37 62 66 36 65 65 31 38 38 } //1 4b324fc8-1670-01d3-1278-5a47bf6ee188
		$a_00_5 = {66 3a 5c 73 6f 75 72 63 65 5c 63 67 5c 63 67 61 6c 6c 5c 69 64 65 5f 68 61 63 6b 64 72 69 76 65 72 5c 6f 62 6a 66 72 65 5f 77 78 70 5f 78 38 36 5c 69 33 38 36 5c 70 63 69 64 69 73 6b 2e 70 64 62 } //1 f:\source\cg\cgall\ide_hackdriver\objfre_wxp_x86\i386\pcidisk.pdb
		$a_02_6 = {68 74 74 70 3a 2f 2f [0-30] 2f 65 6c 66 5f 6c 69 73 74 6f 2e 74 78 74 } //1
		$a_00_7 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //1 CreateObject("ADODB.Stream")
		$a_00_8 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Shell.Application")
		$a_00_9 = {22 4d 69 22 2b 22 63 72 6f 73 6f 66 74 2e 58 4d 22 2b 22 4c 48 54 54 50 22 } //1 "Mi"+"crosoft.XM"+"LHTTP"
		$a_02_10 = {63 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 63 74 66 6d 6f 6e ?? 2e 65 78 65 } //1
		$a_00_11 = {66 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 6f 6d 5c 63 6f 6d 72 65 63 66 67 2e 65 78 65 } //1 f:\windows\system32\com\comrecfg.exe
		$a_00_12 = {72 65 61 64 5f 70 65 5f 69 6e 66 6f 20 73 75 63 63 65 73 73 65 64 } //1 read_pe_info successed
		$a_00_13 = {73 6f 72 72 79 69 6c 6f 76 65 79 6f 75 } //1 sorryiloveyou
		$a_00_14 = {72 65 63 65 69 76 65 64 20 65 78 69 74 20 73 69 67 6e 61 6c 2c 20 65 78 69 74 65 64 2e 2e } //1 received exit signal, exited..
		$a_00_15 = {8b d0 c1 fa 03 8a 14 32 8a c8 80 e1 07 d2 fa 80 e2 01 88 90 c0 76 41 00 40 83 f8 40 7c e2 33 c0 0f be 88 60 6f 40 00 8a 91 bf 76 41 00 0f be 88 61 6f 40 00 88 90 18 6f 41 00 8a 91 bf 76 41 00 0f be 88 62 6f 40 00 88 90 19 6f 41 00 8a 91 bf 76 41 00 0f be 88 63 6f 40 00 88 90 1a 6f 41 00 8a 91 bf 76 41 00 88 90 1b 6f 41 00 83 c0 04 83 f8 40 7c ac 8a 44 24 24 84 c0 8b 5c 24 20 ba 10 00 00 00 8b ca be 18 6f 41 00 bf c0 76 41 00 f3 a5 0f 85 91 00 00 00 a1 } //4
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_02_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1+(#a_00_15  & 1)*4) >=9
 
}