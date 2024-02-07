
rule Trojan_Win32_Dridex_NZ_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 65 73 74 72 69 63 74 28 } //01 00  restrict(
		$a_81_1 = {5c 6b 69 6e 67 50 61 69 6e 74 5c 62 6f 78 2e 70 64 62 } //01 00  \kingPaint\box.pdb
		$a_81_2 = {5f 6e 65 78 74 61 66 74 65 72 } //01 00  _nextafter
		$a_81_3 = {57 6f 72 64 61 62 6c 65 } //01 00  Wordable
		$a_81_4 = {53 61 69 64 63 61 75 73 65 } //01 00  Saidcause
		$a_81_5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_6 = {41 6c 70 68 61 42 6c 65 6e 64 } //01 00  AlphaBlend
		$a_81_7 = {54 72 61 6e 73 70 61 72 65 6e 74 42 6c 74 } //01 00  TransparentBlt
		$a_81_8 = {47 72 61 64 69 65 6e 74 46 69 6c 6c } //01 00  GradientFill
		$a_81_9 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //01 00  IsProcessorFeaturePresent
		$a_81_10 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 61 73 68 72 6f 61 64 2e 63 6f 6d } //01 00  http://www.washroad.com
		$a_81_11 = {3f 68 3f 70 3f 78 3f } //00 00  ?h?p?x?
	condition:
		any of ($a_*)
 
}