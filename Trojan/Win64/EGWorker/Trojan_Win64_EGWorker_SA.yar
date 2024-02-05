
rule Trojan_Win64_EGWorker_SA{
	meta:
		description = "Trojan:Win64/EGWorker.SA,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 31 30 2e 30 3b 20 57 69 6e 36 34 3b 20 78 36 34 29 20 41 70 70 6c 65 57 65 62 4b 69 74 2f 35 33 37 2e 33 36 20 28 4b 48 54 4d 4c 2c 20 6c 69 6b 65 20 47 65 63 6b 6f 29 20 43 68 72 6f 6d 65 2f 31 30 35 2e 30 2e 30 2e 30 20 53 61 66 61 72 69 2f 35 33 37 2e 33 36 } //Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36  01 00 
		$a_80_1 = {70 61 79 6c 6f 6f 70 } //payloop  01 00 
		$a_80_2 = {72 44 4f 6d 48 5a 73 37 75 5a 69 52 37 67 50 78 31 72 36 6f 53 51 75 45 57 55 6c 5a 54 4c 32 33 } //rDOmHZs7uZiR7gPx1r6oSQuEWUlZTL23  02 00 
	condition:
		any of ($a_*)
 
}