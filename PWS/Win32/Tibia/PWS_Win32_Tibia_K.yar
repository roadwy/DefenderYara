
rule PWS_Win32_Tibia_K{
	meta:
		description = "PWS:Win32/Tibia.K,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {26 6e 6f 74 61 74 6b 61 3d } //01 00  &notatka=
		$a_00_1 = {26 6e 75 6d 65 72 3d } //01 00  &numer=
		$a_00_2 = {74 69 62 69 61 63 6c 69 65 6e 74 } //01 00  tibiaclient
		$a_00_3 = {61 64 64 20 68 6b 6c 6d 5c 73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 72 75 6e 20 2f 76 } //01 00  add hklm\software\microsoft\windows\currentversion\run /v
		$a_00_4 = {63 3a 5c 78 2e 65 78 65 } //0a 00  c:\x.exe
		$a_00_5 = {6f 77 6e 74 69 62 69 61 2e 63 6f 6d } //0a 00  owntibia.com
		$a_02_6 = {ba 03 00 00 00 e8 90 01 04 8b 45 90 01 01 e8 90 01 04 50 68 90 01 04 68 90 01 04 6a 00 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}