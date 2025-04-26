
rule Trojan_Win32_Dridex_OB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {73 74 72 65 74 63 68 57 69 64 65 5c 31 30 30 5f 45 6c 73 65 5c 74 68 65 73 65 4d 6f 72 65 5c 4d 6f 6e 74 68 46 69 6e 64 5c 4c 65 61 73 74 2e 70 64 62 } //1 stretchWide\100_Else\theseMore\MonthFind\Least.pdb
		$a_81_1 = {4d 69 67 68 74 63 6f 77 } //1 Mightcow
		$a_81_2 = {4f 6e 6c 79 72 65 61 64 } //1 Onlyread
		$a_81_3 = {5f 6e 65 78 74 61 66 74 65 72 } //1 _nextafter
		$a_81_4 = {43 4f 4e 4f 55 54 24 } //1 CONOUT$
		$a_81_5 = {41 6c 70 68 61 42 6c 65 6e 64 } //1 AlphaBlend
		$a_81_6 = {54 72 61 6e 73 70 61 72 65 6e 74 42 6c 74 } //1 TransparentBlt
		$a_81_7 = {47 72 61 64 69 65 6e 74 46 69 6c 6c } //1 GradientFill
		$a_81_8 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //1 IsProcessorFeaturePresent
		$a_81_9 = {3f 68 3f 70 3f 78 3f } //1 ?h?p?x?
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}