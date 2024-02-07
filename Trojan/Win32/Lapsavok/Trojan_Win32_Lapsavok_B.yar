
rule Trojan_Win32_Lapsavok_B{
	meta:
		description = "Trojan:Win32/Lapsavok.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {b9 e8 03 00 00 99 f7 f9 89 45 f4 8b c7 b9 e8 03 00 00 99 f7 f9 69 c2 e8 03 00 00 89 45 f8 8d 45 f4 50 6a 00 6a 00 8d 85 ec fe ff ff 50 6a 00 e8 90 01 04 85 c0 7e 5b 90 00 } //01 00 
		$a_03_1 = {e9 0b 02 00 00 c7 45 e0 20 4e 00 00 8b 55 90 01 01 b8 90 01 04 e8 90 00 } //01 00 
		$a_03_2 = {74 3b 6a 00 6a 00 68 01 02 00 00 56 e8 90 01 04 6a 00 6a 00 68 02 02 00 00 56 e8 90 01 04 6a 00 6a 00 6a 10 56 e8 90 00 } //01 00 
		$a_01_3 = {67 65 74 31 2e 70 68 70 3f 73 69 64 3d } //01 00  get1.php?sid=
		$a_01_4 = {69 6e 66 2e 70 68 70 3f 74 70 3d 31 26 73 69 64 3d } //01 00  inf.php?tp=1&sid=
		$a_01_5 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 73 63 20 4d 49 4e 55 54 45 20 2f 6d 6f 20 33 20 2f 74 72 20 22 } //00 00  schtasks.exe /create /sc MINUTE /mo 3 /tr "
	condition:
		any of ($a_*)
 
}