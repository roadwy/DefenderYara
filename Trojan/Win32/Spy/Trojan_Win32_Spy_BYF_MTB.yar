
rule Trojan_Win32_Spy_BYF_MTB{
	meta:
		description = "Trojan:Win32/Spy.BYF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_80_0 = {53 74 65 61 6c 69 6e 67 20 42 72 6f 77 73 65 72 73 } //Stealing Browsers  2
		$a_80_1 = {49 6e 76 6f 6b 65 20 53 74 65 61 6c 65 72 50 6c 75 67 69 6e } //Invoke StealerPlugin  2
		$a_80_2 = {47 72 61 62 62 69 6e 67 20 64 69 73 63 6f 72 64 20 74 6f 6b 65 6e 73 } //Grabbing discord tokens  1
		$a_80_3 = {47 72 61 62 62 69 6e 67 20 70 61 73 73 77 6f 72 64 73 } //Grabbing passwords  1
		$a_80_4 = {50 61 73 73 6d 61 6e 20 44 61 74 61 } //Passman Data  1
		$a_80_5 = {43 72 65 64 69 74 20 43 61 72 64 73 } //Credit Cards  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=8
 
}