
rule Trojan_Win64_WoolenGoldfish_LK_MTB{
	meta:
		description = "Trojan:Win64/WoolenGoldfish.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {4c 8b a3 00 00 00 00 41 52 4d 89 da 4d 21 e2 4d 01 d2 4d 01 dc 4d 29 d4 41 5a 4c 89 a3 00 00 00 00 90 02 ff e9 90 00 } //01 00 
		$a_01_1 = {63 3a 5c 77 72 61 70 70 65 72 73 5c 61 67 65 6e 74 5f 77 72 61 70 70 65 72 5c 77 72 61 70 70 65 72 5f } //00 00  c:\wrappers\agent_wrapper\wrapper_
	condition:
		any of ($a_*)
 
}