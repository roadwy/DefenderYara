
rule TrojanDownloader_Win32_Janabanc_B_bit{
	meta:
		description = "TrojanDownloader:Win32/Janabanc.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {4a 61 6e 65 6c 61 73 64 6f 57 4e } //01 00  JanelasdoWN
		$a_01_1 = {38 47 46 46 34 58 4c 42 37 57 48 4d 37 58 37 58 4b 4c 4a 33 51 45 59 4e 4c 47 42 54 34 41 46 32 48 4c 37 42 39 48 } //01 00  8GFF4XLB7WHM7X7XKLJ3QEYNLGBT4AF2HL7B9H
		$a_00_2 = {73 61 4e 6f 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 12 73 61 55 73 65 72 6e 61 6d 65 50 61 73 73 77 6f 72 64 07 49 64 53 6f 63 6b 73 } //01 00 
		$a_03_3 = {c2 08 00 53 a1 90 01 04 83 38 00 74 90 01 01 8b 1d 90 01 04 8b 1b ff d3 5b c3 90 01 01 55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}