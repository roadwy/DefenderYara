
rule Trojan_Win32_ConAtt_SE{
	meta:
		description = "Trojan:Win32/ConAtt.SE,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-20] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-20] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //10
		$a_00_1 = {67 00 65 00 74 00 2d 00 63 00 6f 00 6e 00 74 00 65 00 6e 00 74 00 } //1 get-content
		$a_00_2 = {66 00 6f 00 72 00 65 00 61 00 63 00 68 00 2d 00 6f 00 62 00 6a 00 65 00 63 00 74 00 } //1 foreach-object
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=12
 
}