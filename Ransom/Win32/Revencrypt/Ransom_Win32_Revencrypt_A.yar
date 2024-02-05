
rule Ransom_Win32_Revencrypt_A{
	meta:
		description = "Ransom:Win32/Revencrypt.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0f 00 00 02 00 "
		
	strings :
		$a_80_0 = {69 64 3d 46 38 41 45 36 41 34 35 38 44 44 30 31 43 39 42 44 58 26 63 6f 75 6e 74 3d } //id=F8AE6A458DD01C9BDX&count=  01 00 
		$a_80_1 = {25 73 25 30 38 58 25 30 38 58 25 30 38 58 25 30 38 58 2e 25 73 } //%s%08X%08X%08X%08X.%s  01 00 
		$a_80_2 = {3a 5c 55 53 45 52 44 41 54 41 5c 2a 2e 2a } //:\USERDATA\*.*  01 00 
		$a_80_3 = {23 20 21 21 21 48 45 4c 50 5f 46 49 4c 45 21 21 21 20 23 } //# !!!HELP_FILE!!! #  01 00 
		$a_80_4 = {41 43 48 2e 41 44 42 2e 41 44 53 2e 41 49 54 2e 41 4c 2e 41 50 4a 2e } //ACH.ADB.ADS.AIT.AL.APJ.  01 00 
		$a_80_5 = {2f 6a 73 2f 6f 74 68 65 72 5f 73 63 72 69 70 74 73 2f 67 65 74 2e 70 68 70 } ///js/other_scripts/get.php  02 00 
		$a_80_6 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 73 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 25 73 2e 65 78 65 } //%s\Microsofts\Windows NT\%s.exe  01 00 
		$a_80_7 = {4d 53 20 43 6f 6d 6d 6f 6e 20 55 73 65 72 20 49 6e 74 65 72 66 61 63 65 } //MS Common User Interface  01 00 
		$a_80_8 = {25 30 38 58 25 30 38 58 5f 57 69 6e 64 6f 77 73 5f 44 65 66 65 6e 64 65 72 } //%08X%08X_Windows_Defender  01 00 
		$a_80_9 = {25 30 38 58 25 30 38 58 44 58 } //%08X%08XDX  02 00 
		$a_80_10 = {4d 49 47 66 4d 41 30 47 43 53 71 47 53 49 62 33 44 51 45 42 41 51 55 41 41 34 47 4e 41 44 43 42 69 51 4b 42 67 51 43 51 72 4f 33 45 75 46 45 6c 73 71 32 63 79 58 2b 6d 67 57 4a 34 6c 6e 4b 35 } //MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQrO3EuFElsq2cyX+mgWJ4lnK5  01 00 
		$a_80_11 = {56 69 72 75 73 20 61 6e 64 20 73 70 79 77 61 72 65 20 64 65 66 69 6e 69 74 69 6f 6e 73 20 63 6f 75 6c 64 6e 27 74 20 62 65 20 75 70 64 61 74 65 64 2e } //Virus and spyware definitions couldn't be updated.  01 00 
		$a_80_12 = {3d 3d 3d 45 4e 47 4c 49 53 48 3d 3d 3d } //===ENGLISH===  01 00 
		$a_80_13 = {25 73 5c 25 73 2e 54 58 54 } //%s\%s.TXT  01 00 
		$a_80_14 = {61 67 6e 74 73 76 63 2e 65 78 65 69 73 71 6c 70 6c 75 73 73 76 63 2e 65 78 65 } //agntsvc.exeisqlplussvc.exe  00 00 
		$a_00_15 = {5d 04 00 00 f2 9c } //03 80 
	condition:
		any of ($a_*)
 
}