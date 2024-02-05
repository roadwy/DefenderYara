
rule Trojan_Win32_CoinLoader_SM_MTB{
	meta:
		description = "Trojan:Win32/CoinLoader.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 a1 18 00 00 00 56 33 f6 8b 40 30 8b 40 0c 8b 40 0c 8b 08 85 c9 74 } //01 00 
		$a_02_1 = {8a 1a 8d 43 90 01 01 3c 90 01 01 77 03 80 c3 90 01 01 0f be c3 83 c2 90 01 01 33 f8 c1 c7 0d 47 66 39 32 75 90 01 01 81 ff 90 01 04 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}