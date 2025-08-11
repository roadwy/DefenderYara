
rule Trojan_Win32_ClickFix_DFO_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DFO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,ffffff82 00 ffffff82 00 04 00 00 "
		
	strings :
		$a_00_0 = {2e 00 73 00 65 00 6e 00 64 00 28 00 29 00 3b 00 69 00 65 00 78 00 28 00 24 00 } //100 .send();iex($
		$a_00_1 = {6f 00 70 00 65 00 6e 00 28 00 27 00 47 00 45 00 54 00 27 00 2c 00 24 00 } //10 open('GET',$
		$a_00_2 = {72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 54 00 65 00 78 00 74 00 } //10 responseText
		$a_02_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-20] 3b 00 24 00 } //10
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10) >=130
 
}