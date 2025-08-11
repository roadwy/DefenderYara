
rule Trojan_Win64_PrairieWiper_A{
	meta:
		description = "Trojan:Win64/PrairieWiper.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 61 6b 65 20 73 79 73 74 65 6d 20 75 6e 62 6f 6f 74 61 62 6c 65 20 62 79 20 77 69 70 69 6e 67 20 63 72 69 74 69 63 61 6c 20 4f 53 20 66 69 6c 65 73 } //1 Make system unbootable by wiping critical OS files
		$a_01_1 = {52 65 73 74 61 72 74 20 73 79 73 74 65 6d 20 61 66 74 65 72 20 63 6f 6d 70 6c 65 74 69 6f 6e } //1 Restart system after completion
		$a_01_2 = {4e 75 6d 62 65 72 20 6f 66 20 6f 76 65 72 77 72 69 74 65 20 70 61 73 73 65 73 20 28 31 2d 37 29 } //1 Number of overwrite passes (1-7)
		$a_01_3 = {44 45 53 54 52 55 43 54 49 4f 4e 20 4d 4f 44 45 3a 20 54 61 72 67 65 74 69 6e 67 20 73 79 73 74 65 6d 20 64 72 69 76 65 20 6f 6e 6c 79 } //1 DESTRUCTION MODE: Targeting system drive only
		$a_01_4 = {57 41 52 4e 49 4e 47 3a 20 57 69 70 65 20 69 6e 63 6f 6d 70 6c 65 74 65 20 66 6f 72 20 25 73 3a 20 25 64 20 6f 66 20 25 64 20 66 69 6c 65 73 20 77 69 70 65 64 20 28 25 2e 32 66 25 25 29 } //1 WARNING: Wipe incomplete for %s: %d of %d files wiped (%.2f%%)
		$a_01_5 = {5b 50 48 41 53 45 20 31 5d 20 44 65 73 74 72 6f 79 69 6e 67 20 70 61 72 74 69 74 69 6f 6e 20 73 74 72 75 63 74 75 72 65 73 2e 2e 2e } //1 [PHASE 1] Destroying partition structures...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}