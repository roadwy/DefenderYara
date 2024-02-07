
rule Trojan_Win32_Boxter_CB_MTB{
	meta:
		description = "Trojan:Win32/Boxter.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 3c 0f be 5d 00 33 5c 24 30 53 8b 6c 24 40 58 88 45 00 8b 5c 24 3c 43 89 5c 24 3c ff 44 24 28 0f } //01 00 
		$a_01_1 = {43 41 4c 4c 20 6d 66 6c 69 6e 6b 2e 62 61 74 } //01 00  CALL mflink.bat
		$a_01_2 = {63 6f 70 79 20 70 72 6f 79 65 63 74 6f 5c 6d 66 6c 69 6e 6b 2e 62 61 74 20 77 67 65 74 5c 77 67 65 74 5f 33 32 62 69 74 5c } //01 00  copy proyecto\mflink.bat wget\wget_32bit\
		$a_01_3 = {25 74 65 6d 70 25 5c 67 65 74 61 64 6d 69 6e 2e 76 62 73 } //00 00  %temp%\getadmin.vbs
	condition:
		any of ($a_*)
 
}