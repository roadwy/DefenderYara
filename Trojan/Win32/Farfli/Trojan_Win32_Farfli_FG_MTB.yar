
rule Trojan_Win32_Farfli_FG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {8a 5c 24 10 02 d1 8b 4c 24 28 83 e6 03 33 f5 8a 0c b1 32 4c 24 18 8b 6c 24 10 32 d8 02 cb 32 d1 28 17 0f b6 07 81 c5 47 86 c8 61 83 6c 24 14 01 89 6c 24 10 0f 85 } //01 00 
		$a_81_1 = {44 61 74 65 50 69 63 6b 65 72 44 65 6d 6f 2e 45 58 45 } //00 00  DatePickerDemo.EXE
	condition:
		any of ($a_*)
 
}