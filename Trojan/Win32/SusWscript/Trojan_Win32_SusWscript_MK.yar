
rule Trojan_Win32_SusWscript_MK{
	meta:
		description = "Trojan:Win32/SusWscript.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 wscript
		$a_00_1 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 } //1 appdata\local\temp
		$a_00_2 = {62 00 64 00 61 00 74 00 61 00 2e 00 76 00 62 00 73 00 20 00 2f 00 2f 00 62 00 } //1 bdata.vbs //b
		$a_00_3 = {61 00 61 00 30 00 36 00 65 00 33 00 39 00 65 00 2d 00 37 00 38 00 37 00 36 00 2d 00 34 00 62 00 61 00 33 00 2d 00 62 00 65 00 65 00 65 00 2d 00 34 00 32 00 62 00 64 00 38 00 30 00 66 00 66 00 33 00 36 00 32 00 66 00 } //-1 aa06e39e-7876-4ba3-beee-42bd80ff362f
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}
rule Trojan_Win32_SusWscript_MK_2{
	meta:
		description = "Trojan:Win32/SusWscript.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 wscript
		$a_00_1 = {61 00 70 00 70 00 64 00 61 00 74 00 61 00 5c 00 6c 00 6f 00 63 00 61 00 6c 00 5c 00 74 00 65 00 6d 00 70 00 } //1 appdata\local\temp
		$a_00_2 = {62 00 64 00 61 00 74 00 61 00 2e 00 76 00 62 00 73 00 20 00 2f 00 2f 00 62 00 } //1 bdata.vbs //b
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}