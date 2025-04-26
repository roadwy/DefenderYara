
rule Trojan_WinNT_Adwind_YD_MTB{
	meta:
		description = "Trojan:WinNT/Adwind.YD!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 67 75 64 65 62 75 76 68 77 6a 63 6d 77 6c 61 66 } //1 agudebuvhwjcmwlaf
		$a_00_1 = {7b 68 6f 6e 6d 7a 6b 69 73 6d 62 7b } //1 {honmzkismb{
		$a_00_2 = {6f 7e 6b 7f 6c 6b 78 68 } //1 繯罫歬桸
		$a_00_3 = {75 66 73 71 74 62 76 72 6b 70 79 63 7d 73 6c 71 } //1 ufsqtbvrkpyc}slq
		$a_00_4 = {69 7a 6f 6e 6d 7a 6b 7b 61 6d 62 } //1 izonmzk{amb
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}