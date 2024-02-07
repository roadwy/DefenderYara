
rule Trojan_Win32_Shtcatu_B_bit{
	meta:
		description = "Trojan:Win32/Shtcatu.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f be 85 98 f9 ff ff 83 f8 61 0f 85 f2 00 00 00 0f be 95 99 f9 ff ff 83 fa 58 0f 85 e2 00 00 00 0f be 8d 9a f9 ff ff 83 f9 63 0f 85 d2 00 00 00 0f be 85 9b f9 ff ff 83 f8 65 0f 85 c2 00 00 00 6a 01 68 90 01 04 e8 90 00 } //01 00 
		$a_01_1 = {48 4b 43 55 5c 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {52 45 47 5f 53 5a 20 2f 46 20 2f 44 20 22 43 3a 5c 74 65 6d 70 } //01 00  REG_SZ /F /D "C:\temp
		$a_03_3 = {63 6c 61 6d 61 74 30 2e 64 75 63 6b 64 6e 73 2e 6f 72 67 90 02 10 53 62 69 65 44 6c 6c 90 00 } //01 00 
		$a_01_4 = {63 61 70 74 75 72 61 2e 62 6d 70 } //00 00  captura.bmp
	condition:
		any of ($a_*)
 
}