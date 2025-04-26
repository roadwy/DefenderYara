
rule Trojan_BAT_Disfa_ACH_MTB{
	meta:
		description = "Trojan:BAT/Disfa.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {34 46 55 47 34 61 54 61 4e 6e 69 42 47 62 74 6d 30 48 76 67 48 50 43 59 62 57 43 4d 39 4e 43 4d 66 54 69 67 6e 48 42 4d 35 56 44 63 62 49 7a 73 62 59 44 77 34 47 41 77 34 47 72 65 39 74 69 67 31 56 7a 67 75 55 64 71 30 6b 6a } //4FUG4aTaNniBGbtm0HvgHPCYbWCM9NCMfTignHBM5VDcbIzsbYDw4GAw4Gre9tig1VzguUdq0kj  3
		$a_80_1 = {74 76 51 71 61 61 6d 61 61 61 61 65 61 61 61 61 } //tvQqaamaaaaeaaaa  3
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  3
		$a_80_3 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //get_CurrentDomain  3
		$a_80_4 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 } //get_EntryPoint  3
		$a_80_5 = {55 70 54 6f 4c 6f 77 41 6e 64 52 65 76 65 72 73 65 } //UpToLowAndReverse  3
		$a_80_6 = {43 6f 6d 70 61 72 65 53 74 72 69 6e 67 } //CompareString  3
		$a_80_7 = {41 70 70 65 6e 64 } //Append  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}