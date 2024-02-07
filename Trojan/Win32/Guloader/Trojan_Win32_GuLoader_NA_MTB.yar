
rule Trojan_Win32_GuLoader_NA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {45 6e 67 6c 69 73 68 2e 74 69 70 73 } //03 00  English.tips
		$a_81_1 = {4d 44 54 32 44 46 58 2e 44 4c 4c } //03 00  MDT2DFX.DLL
		$a_81_2 = {28 69 20 30 2c 69 20 30 78 31 30 30 30 30 30 2c 20 69 20 30 78 33 30 30 30 2c 20 69 20 30 78 34 30 29 70 2e 72 33 } //03 00  (i 0,i 0x100000, i 0x3000, i 0x40)p.r3
		$a_81_3 = {43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72 } //03 00  CommonFilesDir
		$a_81_4 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 } //03 00  C:\Program Files
		$a_81_5 = {43 4f 50 59 49 4e 47 2e 74 78 74 } //03 00  COPYING.txt
		$a_81_6 = {77 69 6e 69 6e 69 74 2e 69 6e 69 } //00 00  wininit.ini
	condition:
		any of ($a_*)
 
}