
rule Trojan_Win32_BHO_BP{
	meta:
		description = "Trojan:Win32/BHO.BP,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 6d 65 5c 53 50 54 49 50 49 4d 45 52 53 2e 69 6e 69 } //1 ime\SPTIPIMERS.ini
		$a_00_1 = {43 3a 5c 50 52 4f 47 52 41 7e 31 5c 70 69 70 69 } //1 C:\PROGRA~1\pipi
		$a_00_2 = {64 65 6c 20 44 65 6c 54 65 6d 70 2e 62 61 74 } //1 del DelTemp.bat
		$a_03_3 = {80 7d fe 00 74 30 83 7e 04 00 0f 95 c0 84 d8 74 18 ff 76 10 68 ?? ?? ?? ?? ff 75 f4 8d 45 f4 ba 03 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}