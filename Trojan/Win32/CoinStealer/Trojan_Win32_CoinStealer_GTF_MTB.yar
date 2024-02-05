
rule Trojan_Win32_CoinStealer_GTF_MTB{
	meta:
		description = "Trojan:Win32/CoinStealer.GTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {32 c5 88 42 03 8a 42 f4 32 45 fd 88 42 04 8a 42 f5 32 c1 88 42 05 8a 42 f6 32 c4 43 88 42 06 83 c2 90 01 01 83 fb 2c 0f 82 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}