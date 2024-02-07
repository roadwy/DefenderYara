
rule TrojanSpy_Win32_Ranbyus_P{
	meta:
		description = "TrojanSpy:Win32/Ranbyus.P,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 02 d1 e8 4a 75 ee 89 04 8d 90 09 05 00 35 90 00 } //01 00 
		$a_01_1 = {42 53 52 5f 41 4e 59 43 52 4c 46 29 } //01 00  BSR_ANYCRLF)
		$a_01_2 = {c1 cf 0d 03 f8 e2 f0 81 ff 5b bc 4a 6a 8b 5a 10 8b 12 75 db } //01 00 
		$a_03_3 = {73 65 73 73 69 6f 6e 3d 90 02 08 76 3d 90 02 08 6e 61 6d 65 3d 90 02 08 6d 6f 64 75 6c 65 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}