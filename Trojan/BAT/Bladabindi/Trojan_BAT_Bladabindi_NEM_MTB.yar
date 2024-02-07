
rule Trojan_BAT_Bladabindi_NEM_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 16 11 05 6f 75 00 00 0a 00 08 06 16 06 8e b7 6f 81 00 00 0a 13 05 00 11 05 16 fe 02 13 06 11 06 } //01 00 
		$a_01_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 6b 00 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00 } //01 00  cmd.exe /k ping 0 & del
		$a_01_2 = {52 00 75 00 6e 00 46 00 69 00 6c 00 65 00 46 00 72 00 6f 00 6d 00 4c 00 69 00 6e 00 6b 00 } //01 00  RunFileFromLink
		$a_01_3 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 46 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 } //00 00  SELECT * FROM FirewallProduct
	condition:
		any of ($a_*)
 
}