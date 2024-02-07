
rule Trojan_Win32_Murureg_B{
	meta:
		description = "Trojan:Win32/Murureg.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 70 68 70 3f 76 65 72 3d 25 56 45 52 25 26 63 76 65 72 3d 25 43 56 45 52 25 26 69 64 3d 25 49 44 25 } //01 00  .php?ver=%VER%&cver=%CVER%&id=%ID%
		$a_02_1 = {66 0f be 05 90 01 04 33 c9 0f af 05 90 01 04 39 0d 90 01 04 66 a3 90 01 04 75 0c 39 4c 24 08 88 0d 90 01 04 74 07 c6 05 90 01 04 01 66 39 0d 90 01 04 75 0e 38 0d 90 01 04 89 0d 90 01 04 74 0a c7 05 90 01 04 01 00 00 00 0f bf c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}