
rule TrojanSpy_Win32_Goldun_FC{
	meta:
		description = "TrojanSpy:Win32/Goldun.FC,SIGNATURE_TYPE_PEHSTR_EXT,34 00 32 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 62 72 6f 77 73 65 6d 75 2e 64 6c 6c } //0a 00  C:\WINDOWS\SYSTEM32\browsemu.dll
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 2d 67 6f 6c 64 2e 63 6f 6d 2f } //0a 00  https://www.e-gold.com/
		$a_00_2 = {2f 61 63 63 74 2f 61 69 2e 61 73 70 3f 63 3d 43 4f } //0a 00  /acct/ai.asp?c=CO
		$a_02_3 = {25 54 45 4d 50 25 5c 73 65 72 76 90 02 04 2e 65 78 65 90 00 } //05 00 
		$a_00_4 = {26 57 4f 52 54 48 5f 4f 46 3d 47 6f 6c 64 26 4d 65 6d 6f 3d 26 } //05 00  &WORTH_OF=Gold&Memo=&
		$a_00_5 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //01 00  SOFTWARE\Microsoft\Internet Account Manager\Accounts
		$a_00_6 = {63 6f 6d 63 73 69 35 2e 64 6c 6c } //01 00  comcsi5.dll
		$a_00_7 = {73 72 76 73 77 63 32 2e 64 6c 6c } //00 00  srvswc2.dll
	condition:
		any of ($a_*)
 
}