
rule TrojanSpy_Win32_Kimsuk_A{
	meta:
		description = "TrojanSpy:Win32/Kimsuk.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c1 e9 02 f3 a5 8b c8 33 c0 83 e1 03 85 db f3 a4 7e 0e 8a 0c 10 80 f1 99 88 0c 10 40 3b c3 7c f2 } //01 00 
		$a_03_1 = {5b 52 4d 4f 55 53 45 5d 00 90 02 04 5b 4c 4d 4f 55 53 45 5d 00 90 02 04 5b 44 57 4e 5d 00 90 02 04 5b 55 50 5d 00 90 02 5b 4c 54 5d 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}