
rule Trojan_Win32_QQpass_U{
	meta:
		description = "Trojan:Win32/QQpass.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 da 32 1c 07 80 f3 80 46 88 18 c6 04 01 00 40 3b f5 7c d7 } //01 00 
		$a_01_1 = {99 b9 0a 00 00 00 f7 f9 80 c2 30 88 54 34 10 46 83 fe 05 7c e9 } //00 00 
	condition:
		any of ($a_*)
 
}