
rule Trojan_Win32_Qimiral_A{
	meta:
		description = "Trojan:Win32/Qimiral.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 69 63 71 2e 65 78 65 } //01 00  taskkill /F /IM icq.exe
		$a_00_1 = {6d 6f 6e 69 74 6f 72 3f 73 69 64 3d } //01 00  monitor?sid=
		$a_00_2 = {48 31 4e 31 00 } //01 00 
		$a_01_3 = {50 6a 04 8d 45 f4 50 68 40 78 6b 00 56 e8 } //01 00 
		$a_01_4 = {8a 45 ff 04 e0 2c 5f 72 06 04 bf 2c 40 73 1c } //00 00 
	condition:
		any of ($a_*)
 
}