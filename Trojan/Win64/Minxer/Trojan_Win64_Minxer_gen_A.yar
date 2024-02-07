
rule Trojan_Win64_Minxer_gen_A{
	meta:
		description = "Trojan:Win64/Minxer.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 6d 69 6e 65 72 64 20 5b 4f 50 54 49 4f 4e 53 5d } //01 00  Usage: minerd [OPTIONS]
		$a_01_1 = {67 65 74 77 6f 72 6b 22 2c 20 22 70 61 72 61 6d 73 22 3a 20 5b 20 22 25 73 22 20 5d 2c 20 22 69 64 22 3a 31 } //01 00  getwork", "params": [ "%s" ], "id":1
		$a_01_2 = {25 64 20 6d 69 6e 65 72 20 74 68 72 65 61 64 73 20 73 74 61 72 74 65 64 2c 20 75 73 69 6e 67 20 27 25 73 27 20 61 6c 67 6f 72 69 74 68 6d 2e } //00 00  %d miner threads started, using '%s' algorithm.
	condition:
		any of ($a_*)
 
}