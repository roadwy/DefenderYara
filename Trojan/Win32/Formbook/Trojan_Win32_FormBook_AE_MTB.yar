
rule Trojan_Win32_FormBook_AE_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 00 72 00 64 00 69 00 6b 00 61 00 74 00 69 00 76 00 69 00 6e 00 74 00 65 00 72 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00 64 00 65 00 72 00 62 00 6f 00 65 00 6e 00 64 00 65 00 73 00 69 00 6e 00 64 00 6f 00 6e 00 65 00 76 00 6b 00 6b 00 } //01 00  Prdikativintermessagederboendesindonevkk
		$a_01_1 = {4f 00 70 00 67 00 61 00 6e 00 67 00 65 00 6e 00 65 00 73 00 6d 00 61 00 72 00 6b 00 65 00 64 00 73 00 6f 00 70 00 31 00 } //01 00  Opgangenesmarkedsop1
		$a_01_2 = {42 00 64 00 65 00 70 00 72 00 61 00 6b 00 73 00 69 00 73 00 65 00 6e 00 73 00 65 00 72 00 6d 00 69 00 6e 00 6f 00 69 00 73 00 73 00 70 00 6f 00 6f 00 6e 00 6c 00 69 00 6b 00 65 00 73 00 68 00 65 00 6d 00 69 00 74 00 65 00 68 00 79 00 } //01 00  Bdepraksisenserminoisspoonlikeshemitehy
		$a_01_3 = {73 00 6e 00 6f 00 64 00 73 00 6a 00 6c 00 73 00 73 00 74 00 6f 00 72 00 } //01 00  snodsjlsstor
		$a_00_4 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00  MSVBVM60.DLL
	condition:
		any of ($a_*)
 
}