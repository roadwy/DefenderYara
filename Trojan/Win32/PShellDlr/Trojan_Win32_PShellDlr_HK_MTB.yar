
rule Trojan_Win32_PShellDlr_HK_MTB{
	meta:
		description = "Trojan:Win32/PShellDlr.HK!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6a 00 6a 00 05 00 00 "
		
	strings :
		$a_02_0 = {2f 00 6d 00 69 00 6e 00 20 00 21 00 [0-16] 6c 00 } //100
		$a_00_1 = {3d 00 70 00 6f 00 77 00 26 00 } //50 =pow&
		$a_00_2 = {3d 00 65 00 72 00 73 00 26 00 } //50 =ers&
		$a_00_3 = {2e 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 74 00 72 00 69 00 6e 00 67 00 } //1 .downloadstring
		$a_00_4 = {69 00 65 00 78 00 20 00 24 00 } //5 iex $
	condition:
		((#a_02_0  & 1)*100+(#a_00_1  & 1)*50+(#a_00_2  & 1)*50+(#a_00_3  & 1)*1+(#a_00_4  & 1)*5) >=106
 
}