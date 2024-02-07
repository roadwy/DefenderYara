
rule Trojan_WinNT_Finkmilt_gen_A{
	meta:
		description = "Trojan:WinNT/Finkmilt.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 c7 46 08 73 00 90 09 15 00 66 c7 46 08 90 01 01 00 38 1d 90 01 04 74 90 01 01 57 ff 15 90 00 } //01 00 
		$a_01_1 = {72 f0 8d 85 7c ff ff ff 50 8d 45 cc } //01 00 
		$a_01_2 = {72 f5 8d 85 60 ff ff ff 50 8d 85 2c ff ff ff } //01 00 
		$a_01_3 = {4c 65 54 65 72 76 69 63 65 45 65 73 63 72 69 71 } //00 00  LeTerviceEescriq
	condition:
		any of ($a_*)
 
}