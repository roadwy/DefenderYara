
rule Ransom_Win32_Tibbar_A{
	meta:
		description = "Ransom:Win32/Tibbar.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 3e 1c 24 4a 74 2f 3d 17 a5 3c 92 74 23 3d 15 04 6d 96 74 21 3d 20 16 33 aa 74 1a 3d 76 09 f1 c8 74 0e 3d 14 7a 51 e2 74 0c 3d 00 5a a0 e5 75 08 83 e7 bf eb 03 83 e7 ef 8d 85 d4 fd ff ff } //1
		$a_00_1 = {25 73 2c 23 32 20 25 73 00 00 00 41 44 4d 49 4e 24 00 00 63 73 63 63 2e 64 61 74 00 00 00 00 00 00 00 00 4f 00 6f 00 70 00 73 00 21 00 20 00 59 00 6f 00 75 00 72 00 20 00 66 00 69 00 6c 00 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}
rule Ransom_Win32_Tibbar_A_2{
	meta:
		description = "Ransom:Win32/Tibbar.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 12 00 00 "
		
	strings :
		$a_01_0 = {57 65 20 47 75 61 72 61 6e 74 65 65 20 74 68 61 74 20 79 6f 75 20 63 61 6e 20 72 65 63 6f 76 65 72 20 61 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 73 61 66 65 6c 79 2e 20 41 6c 6c 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 64 6f 20 69 73 20 73 75 62 6d 69 74 20 74 68 65 20 70 61 79 6d 65 6e 74 20 61 6e 64 20 67 65 74 20 74 68 65 20 64 65 63 72 79 70 74 69 6f 6e 20 70 61 73 73 77 6f 72 64 2e } //5 We Guarantee that you can recover all your files safely. All you need to do is submit the payment and get the decryption password.
		$a_01_1 = {63 61 66 6f 72 73 73 7a 74 78 71 7a 66 32 6e 6d 2e 6f 6e 69 6f 6e } //2 caforssztxqzf2nm.onion
		$a_00_2 = {69 6e 66 70 75 62 2e 64 61 74 2c 23 31 } //2 infpub.dat,#1
		$a_80_3 = {2e 33 64 73 2e 37 7a 2e 61 63 63 64 62 2e 61 69 2e 61 73 6d 2e 61 73 70 2e 61 73 70 78 2e 61 76 68 64 2e 62 61 63 6b 2e 62 61 6b 2e 62 6d 70 2e 62 72 77 2e 63 2e 63 61 62 2e 63 63 2e } //.3ds.7z.accdb.ai.asm.asp.aspx.avhd.back.bak.bmp.brw.c.cab.cc.  1
		$a_80_4 = {2e 5c 64 63 72 79 70 74 } //.\dcrypt  1
		$a_80_5 = {2f 63 20 73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 46 20 2f 54 4e 20 72 68 61 65 67 61 6c } ///c schtasks /Delete /F /TN rhaegal  1
		$a_80_6 = {44 69 73 61 62 6c 65 20 79 6f 75 72 20 61 6e 74 69 2d 76 69 72 75 73 20 61 6e 64 20 61 6e 74 69 2d 6d 61 6c 77 61 72 65 20 70 72 6f 67 72 61 6d 73 } //Disable your anti-virus and anti-malware programs  1
		$a_80_7 = {45 6e 74 65 72 20 70 61 73 73 77 6f 72 64 23 32 3a } //Enter password#2:  1
		$a_80_8 = {4d 49 49 42 49 6a 41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51 45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67 4b 43 41 51 45 41 35 63 6c 44 75 56 46 72 35 73 51 78 5a 2b 66 } //MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5clDuVFr5sQxZ+f  1
		$a_80_9 = {2f 43 72 65 61 74 65 20 2f 53 43 20 4f 4e 43 45 20 2f 54 4e 20 76 69 73 65 72 69 6f 6e 5f 25 75 20 2f 52 55 20 53 59 53 54 45 4d 20 2f 54 52 20 22 25 77 73 22 20 2f 53 54 20 25 30 32 64 3a 25 30 32 64 3a 30 30 } ///Create /SC ONCE /TN viserion_%u /RU SYSTEM /TR "%ws" /ST %02d:%02d:00  1
		$a_80_10 = {45 6e 74 65 72 20 70 61 73 73 77 6f 72 64 23 31 3a } //Enter password#1:  1
		$a_03_11 = {68 2c 02 00 00 57 68 98 02 00 00 8d 8d ?? ?? ff ff 51 68 1c 00 22 00 } //1
		$a_80_12 = {40 40 73 63 68 74 61 73 6b 73 20 2f 44 65 6c 65 74 65 20 2f 46 20 2f 54 4e 20 72 68 61 65 67 61 6c } //@@schtasks /Delete /F /TN rhaegal  1
		$a_80_13 = {2f 43 72 65 61 74 65 20 2f 52 55 20 53 59 53 54 45 4d 20 2f 53 43 20 4f 4e 53 54 41 52 54 20 2f 54 4e 20 72 68 61 65 67 61 6c 20 2f 54 52 } ///Create /RU SYSTEM /SC ONSTART /TN rhaegal /TR  2
		$a_80_14 = {25 77 73 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 25 77 73 2c 23 31 20 25 77 73 } //%ws C:\Windows\%ws,#1 %ws  2
		$a_80_15 = {72 75 6e 64 6c 6c 33 32 20 25 73 2c 23 32 20 25 73 } //rundll32 %s,#2 %s  2
		$a_80_16 = {25 77 73 77 65 76 74 75 74 69 6c 20 63 6c 20 25 77 73 20 26 } //%wswevtutil cl %ws &  1
		$a_80_17 = {2f 43 72 65 61 74 65 20 2f 53 43 20 6f 6e 63 65 20 2f 54 4e 20 64 72 6f 67 6f 6e 20 2f 52 55 20 53 59 53 54 45 4d 20 2f 54 52 } ///Create /SC once /TN drogon /RU SYSTEM /TR  2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_03_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*2+(#a_80_14  & 1)*2+(#a_80_15  & 1)*2+(#a_80_16  & 1)*1+(#a_80_17  & 1)*2) >=8
 
}