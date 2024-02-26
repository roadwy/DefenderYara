
rule Trojan_Win32_Razy_GMX_MTB{
	meta:
		description = "Trojan:Win32/Razy.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {31 32 89 d9 09 d8 42 81 c1 90 01 04 f7 d1 b8 90 01 04 47 4b 81 e8 90 01 04 09 d9 81 fa 90 01 04 0f 8c 90 00 } //0a 00 
		$a_03_1 = {21 cb 09 c1 81 c0 90 01 04 31 16 01 c9 81 c1 90 01 04 81 c6 90 01 04 09 c9 bb 90 01 04 40 81 c7 90 01 04 21 db 29 c3 01 c9 81 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}