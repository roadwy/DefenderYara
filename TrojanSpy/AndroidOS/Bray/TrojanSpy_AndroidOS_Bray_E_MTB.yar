
rule TrojanSpy_AndroidOS_Bray_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Bray.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {0c 04 6e 10 90 01 02 04 00 0c 06 1f 06 22 02 6e 10 14 07 04 00 0a 08 32 b8 90 01 02 55 68 74 02 38 08 90 02 05 52 68 e4 00 b1 85 6e 10 90 01 02 04 00 0a 08 6e 10 90 01 02 04 00 0a 09 db 0a 09 02 91 0a 02 0a 91 0c 05 08 b0 a9 6e 59 90 01 02 c4 5a 52 64 e3 00 b0 48 b0 38 b1 85 d8 07 07 01 90 00 } //01 00 
		$a_00_1 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } //01 00 
		$a_00_2 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 50 61 63 6b 61 67 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}