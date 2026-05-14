
rule Trojan_Win32_ClickFix_PAA_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.PAA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 00 27 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //4 ='http://
		$a_00_1 = {69 00 65 00 78 00 28 00 69 00 72 00 6d 00 } //3 iex(irm
		$a_00_2 = {27 00 63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 27 00 20 00 2d 00 73 00 20 00 2d 00 4c 00 } //3 'curl.exe' -s -L
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3) >=10
 
}