
rule Trojan_Win32_MshtaLolBin_B{
	meta:
		description = "Trojan:Win32/MshtaLolBin.B,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 } //1 mshta.exe
		$a_00_1 = {6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 } //1 javascript
		$a_00_2 = {61 00 63 00 74 00 69 00 76 00 65 00 78 00 6f 00 62 00 6a 00 65 00 63 00 74 00 } //1 activexobject
		$a_00_3 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 73 00 68 00 65 00 6c 00 6c 00 } //1 wscript.shell
		$a_00_4 = {2e 00 72 00 75 00 6e 00 28 00 } //1 .run(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}