
rule Trojan_Win32_BazarLoader_CN_MTB{
	meta:
		description = "Trojan:Win32/BazarLoader.CN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_80_0 = {2e 62 61 7a 61 72 } //.bazar  20
		$a_80_1 = {43 61 6e 6e 6f 74 20 72 65 61 64 20 72 65 6d 6f 74 65 20 50 45 42 3a 20 25 6c 75 } //Cannot read remote PEB: %lu  1
		$a_80_2 = {50 72 6f 63 65 73 73 20 44 6f 70 70 65 6c 67 61 6e 67 69 6e 67 20 74 65 73 74 21 } //Process Doppelganging test!  1
		$a_80_3 = {6e 65 74 20 6c 6f 63 61 6c 67 72 6f 75 70 20 22 61 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //net localgroup "administrator  1
		$a_80_4 = {6e 6c 74 65 73 74 20 2f 64 6f 6d 61 69 6e 5f 74 72 75 73 74 73 20 2f 61 6c 6c 5f 74 72 75 73 74 73 } //nltest /domain_trusts /all_trusts  1
	condition:
		((#a_80_0  & 1)*20+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=22
 
}