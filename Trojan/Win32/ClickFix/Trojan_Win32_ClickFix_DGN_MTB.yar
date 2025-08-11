
rule Trojan_Win32_ClickFix_DGN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DGN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffffa3 00 ffffffa3 00 06 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 20 00 24 00 } //50 wscript $
		$a_00_2 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 } //10 ActiveXObject(
		$a_00_3 = {2e 00 73 00 70 00 6c 00 69 00 74 00 28 00 } //1 .split(
		$a_00_4 = {72 00 65 00 76 00 65 00 72 00 73 00 65 00 } //1 reverse
		$a_00_5 = {2e 00 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 54 00 65 00 78 00 74 00 } //1 .responseText
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*50+(#a_00_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=163
 
}