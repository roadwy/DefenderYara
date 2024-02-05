
rule Trojan_Win32_Redline_RPC_MTB{
	meta:
		description = "Trojan:Win32/Redline.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c6 83 e0 03 8a 98 90 01 04 32 9e 90 01 04 e8 90 01 02 00 00 50 e8 90 01 02 00 00 88 9e 90 01 04 46 59 81 fe 90 01 04 72 d4 33 f6 8b c6 83 e0 03 8a 98 90 01 04 32 9e 90 01 04 e8 90 01 02 00 00 50 e8 90 01 02 00 00 88 9e 90 01 04 46 59 81 fe 90 01 04 72 d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}