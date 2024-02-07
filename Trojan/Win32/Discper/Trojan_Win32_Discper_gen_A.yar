
rule Trojan_Win32_Discper_gen_A{
	meta:
		description = "Trojan:Win32/Discper.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {3a 37 37 37 37 00 90 02 05 7b 22 6d 65 74 68 6f 64 22 3a 20 22 67 65 74 77 6f 72 6b 22 2c 20 22 70 61 72 61 6d 73 22 3a 20 5b 5d 2c 20 22 69 64 22 3a 30 90 00 } //01 00 
		$a_01_1 = {34 35 34 48 44 4c 44 74 71 43 4c 53 32 34 45 73 44 41 59 6f 72 66 39 51 41 56 6b 4e 71 51 50 64 4a 54 61 45 42 72 64 69 39 70 56 45 4c 55 48 36 5a 53 55 33 37 56 71 56 38 55 41 6f 54 59 56 37 6b } //00 00  454HDLDtqCLS24EsDAYorf9QAVkNqQPdJTaEBrdi9pVELUH6ZSU37VqV8UAoTYV7k
	condition:
		any of ($a_*)
 
}