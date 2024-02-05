
rule Trojan_Win32_ClipBanker_GME_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.GME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {83 c4 04 33 c0 c7 05 90 01 04 0f 00 00 00 a3 90 01 04 a2 90 01 04 c3 c7 05 90 01 04 54 53 01 10 b9 90 00 } //01 00 
		$a_01_1 = {4c 6f 63 61 6c 5c 45 78 69 74 43 6c 69 70 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}