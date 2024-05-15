
rule Trojan_Win64_AuKill_B{
	meta:
		description = "Trojan:Win64/AuKill.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {5b 2d 5d 20 45 78 63 65 70 74 20 69 6e 20 4b 69 6c 6c 50 72 90 01 01 63 65 73 73 48 61 6e 64 6c 65 73 90 00 } //01 00 
		$a_03_1 = {5b 21 5d 20 4f 70 65 6e 50 72 6f 63 65 73 73 54 6f 6b 65 6e 20 66 61 69 6c 65 64 20 28 54 72 75 90 01 01 74 65 64 49 6e 73 74 61 6c 6c 65 72 2e 65 78 65 29 3a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}