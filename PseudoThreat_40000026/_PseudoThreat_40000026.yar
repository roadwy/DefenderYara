
rule _PseudoThreat_40000026{
	meta:
		description = "!PseudoThreat_40000026,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0d 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {db 5b ba ba ff 4e db 48 b4 43 67 96 51 d3 71 28 } //01 00 
		$a_01_1 = {e7 a8 0e 15 7c a9 16 48 ad 02 48 65 ee f8 c5 ff } //01 00 
		$a_01_2 = {4e 00 65 00 77 00 4d 00 65 00 64 00 69 00 61 00 43 00 6f 00 64 00 65 00 63 00 2e 00 6f 00 63 00 78 00 } //03 00  NewMediaCodec.ocx
		$a_01_3 = {4e 00 65 00 77 00 4d 00 65 00 64 00 69 00 61 00 43 00 6f 00 64 00 65 00 63 00 2e 00 4e 00 65 00 77 00 4d 00 65 00 64 00 69 00 61 00 43 00 6f 00 64 00 65 00 63 00 50 00 72 00 6f 00 70 00 50 00 61 00 67 00 65 00 2e 00 31 00 } //03 00  NewMediaCodec.NewMediaCodecPropPage.1
		$a_01_4 = {4e 65 77 4d 65 64 69 61 43 6f 64 65 63 20 43 6f 6e 74 72 6f 6c 57 } //03 00  NewMediaCodec ControlW
		$a_01_5 = {43 4e 65 77 4d 65 64 69 61 43 6f 64 65 63 43 74 72 6c } //03 00  CNewMediaCodecCtrl
		$a_01_6 = {43 4e 65 77 4d 65 64 69 61 43 6f 64 65 63 50 72 6f 70 50 61 67 65 } //00 00  CNewMediaCodecPropPage
	condition:
		any of ($a_*)
 
}