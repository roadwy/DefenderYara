
rule Trojan_Win32_Dridex_ADS_MTB{
	meta:
		description = "Trojan:Win32/Dridex.ADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {70 61 69 72 2e 70 64 62 } //pair.pdb  3
		$a_80_1 = {64 65 63 69 64 65 5f 70 61 67 65 5c 46 61 76 6f 72 2d 63 68 69 63 6b } //decide_page\Favor-chick  3
		$a_80_2 = {4c 69 74 74 6c 65 20 53 6f } //Little So  3
		$a_80_3 = {47 65 74 50 72 6f 63 65 73 73 57 69 6e 64 6f 77 53 74 61 74 69 6f 6e } //GetProcessWindowStation  3
		$a_80_4 = {47 65 74 55 73 65 72 4f 62 6a 65 63 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 41 } //GetUserObjectInformationA  3
		$a_80_5 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //SystemFunction036  3
		$a_80_6 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}