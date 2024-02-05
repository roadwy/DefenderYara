
rule Trojan_Win32_Redline_IBKP_MTB{
	meta:
		description = "Trojan:Win32/Redline.IBKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a ca 66 8b f0 66 0f ab f6 d3 c0 f8 81 ce 90 01 04 8d b4 15 fc fe ff ff f8 02 c2 f8 81 fd 90 01 04 32 04 37 90 00 } //01 00 
		$a_00_1 = {88 06 0f 84 11 00 00 00 42 3c 76 f9 f5 81 fa 04 01 00 00 0f 82 7b e8 13 00 } //00 00 
	condition:
		any of ($a_*)
 
}