
rule Trojan_Win32_ConAtt_B{
	meta:
		description = "Trojan:Win32/ConAtt.B,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {63 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 [0-20] 2d 00 2d 00 68 00 65 00 61 00 64 00 6c 00 65 00 73 00 73 00 [0-10] 5c 00 5c 00 [0-ff] 64 00 61 00 76 00 77 00 77 00 77 00 72 00 6f 00 6f 00 74 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}