
rule VirTool_Win32_VBInject_gen_LD{
	meta:
		description = "VirTool:Win32/VBInject.gen!LD,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 11 00 00 01 00 "
		
	strings :
		$a_03_0 = {4b 65 72 4f 63 78 00 90 02 0a 46 75 63 6b 42 69 74 44 65 66 90 00 } //0a 00 
		$a_03_1 = {f5 00 00 00 00 f5 00 00 00 00 6c 90 01 01 90 03 01 01 fe ff 6c 90 01 01 90 03 01 01 fe ff 6c 90 01 01 90 03 01 01 fe ff 0a 90 01 01 00 14 00 3c 14 90 00 } //01 00 
		$a_03_2 = {4d 73 5f 6c 6f 6c 00 90 02 0a 46 75 63 6b 4d 73 61 6e 64 4d 73 6e 64 4d 73 90 00 } //01 00 
		$a_01_3 = {73 63 72 77 41 76 73 74 61 6e 64 75 61 6c 6c } //01 00  scrwAvstanduall
		$a_01_4 = {75 5f 6d 5f 73 5f 70 6f 6f 72 5f 74 68 69 6e 00 } //01 00  彵彭彳潰牯瑟楨n
		$a_01_5 = {69 6c 62 61 6c 77 61 79 73 74 68 65 62 65 73 } //01 00  ilbalwaysthebes
		$a_01_6 = {61 79 61 73 74 62 65 73 69 6c 62 68 65 6c 77 } //01 00  ayastbesilbhelw
		$a_01_7 = {73 74 62 61 79 61 65 6c 77 65 73 69 6c 62 68 } //01 00  stbayaelwesilbh
		$a_01_8 = {61 73 74 6c 6c 65 73 62 77 61 79 62 65 69 68 } //01 00  astllesbwaybeih
		$a_01_9 = {74 62 62 73 77 79 73 65 69 68 61 6c 65 6c } //01 00  tbbswyseihalel
		$a_01_10 = {65 73 6c 65 68 62 73 69 61 74 62 77 79 6c } //01 00  eslehbsiatbwyl
		$a_01_11 = {74 75 69 6b 69 64 6e 69 63 6e } //01 00  tuikidnicn
		$a_01_12 = {61 6c 74 62 6c 73 73 79 65 65 69 62 77 68 } //01 00  altblssyeeibwh
		$a_01_13 = {6c 73 73 62 65 69 61 6c 74 62 77 79 65 68 } //01 00  lssbeialtbwyeh
		$a_01_14 = {74 6c 73 73 62 62 65 79 65 68 69 61 6c 77 } //01 00  tlssbbeyehialw
		$a_01_15 = {73 62 62 69 65 65 68 6c 74 6c 61 79 73 77 } //01 00  sbbieehltlaysw
		$a_01_16 = {69 6c 74 62 65 61 79 73 68 65 6c 73 62 77 } //00 00  iltbeayshelsbw
	condition:
		any of ($a_*)
 
}