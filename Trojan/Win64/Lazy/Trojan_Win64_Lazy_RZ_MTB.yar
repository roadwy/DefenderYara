
rule Trojan_Win64_Lazy_RZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 69 6e 66 3a } //2 Go buildinf:
		$a_81_1 = {2f 74 68 65 73 75 6e 77 61 76 65 2f 70 6f 73 6f 73 79 61 6d 62 61 5f 62 6f 74 } //2 /thesunwave/pososyamba_bot
		$a_81_2 = {6d 54 55 51 32 51 50 63 43 46 36 35 44 38 61 35 65 65 4b 78 49 41 71 4f 50 63 72 78 73 78 4f 36 43 7a 48 52 34 73 30 } //1 mTUQ2QPcCF65D8a5eeKxIAqOPcrxsxO6CzHR4s0
		$a_81_3 = {7a 50 41 54 36 43 47 79 36 77 58 65 51 37 4e 74 54 6e 61 54 65 72 66 4b 4f 73 56 36 56 36 46 38 61 67 48 58 46 69 61 7a 44 6b 67 } //1 zPAT6CGy6wXeQ7NtTnaTerfKOsV6V6F8agHXFiazDkg
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=6
 
}