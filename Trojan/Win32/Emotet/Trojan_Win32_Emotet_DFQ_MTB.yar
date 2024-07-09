
rule Trojan_Win32_Emotet_DFQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c9 25 ff 00 00 00 8a 4c 14 20 8b ac 24 ?? ?? ?? ?? 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8b 4c 24 14 8a 04 29 8a 54 14 20 32 c2 88 04 29 } //1
		$a_81_1 = {69 34 48 66 56 41 4b 5a 42 34 50 30 70 65 48 33 30 69 65 44 4d 44 79 5a 55 6d 37 4c 76 47 } //1 i4HfVAKZB4P0peH30ieDMDyZUm7LvG
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}