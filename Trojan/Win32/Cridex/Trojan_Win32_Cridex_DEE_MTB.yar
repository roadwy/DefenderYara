
rule Trojan_Win32_Cridex_DEE_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c3 2b c2 89 1d 90 01 04 03 dd 83 15 90 01 04 00 8d 44 00 ae 8b ea 2b e9 81 c6 90 01 04 8d 44 28 02 8b 6c 24 10 89 35 90 01 04 89 75 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}