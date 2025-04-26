
rule Trojan_Win32_Coppest_A{
	meta:
		description = "Trojan:Win32/Coppest.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_00_0 = {20 00 2d 00 6e 00 6f 00 70 00 20 00 2d 00 6e 00 6f 00 6e 00 69 00 20 00 2d 00 65 00 78 00 65 00 63 00 75 00 74 00 69 00 6f 00 6e 00 70 00 6f 00 6c 00 69 00 63 00 79 00 20 00 62 00 79 00 70 00 61 00 73 00 73 00 20 00 } //10  -nop -noni -executionpolicy bypass 
	condition:
		((#a_00_0  & 1)*10) >=10
 
}