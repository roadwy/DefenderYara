
rule Trojan_Win32_TrickBot_DSV_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 ?? ?? ?? ?? 99 f7 f9 8a 84 14 ?? ?? ?? ?? 8b 54 24 ?? 32 02 88 44 24 } //1
		$a_81_1 = {50 6b 73 63 58 78 31 39 79 36 48 4b 5a 7a 75 36 6d 7e 79 4d 72 59 75 44 70 69 46 64 72 36 31 31 7c 43 38 62 } //1 PkscXx19y6HKZzu6m~yMrYuDpiFdr611|C8b
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}