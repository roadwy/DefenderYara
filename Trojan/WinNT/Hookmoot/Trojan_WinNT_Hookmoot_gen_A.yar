
rule Trojan_WinNT_Hookmoot_gen_A{
	meta:
		description = "Trojan:WinNT/Hookmoot.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 40 01 8b 0d 90 01 04 a3 90 01 04 8b 09 8b 04 81 a3 90 01 04 8d 45 90 01 01 50 68 90 01 04 e8 90 00 } //01 00 
		$a_03_1 = {50 0f 20 c0 a3 90 01 04 25 ff ff fe ff 0f 22 c0 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}