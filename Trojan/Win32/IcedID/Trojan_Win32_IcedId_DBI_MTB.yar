
rule Trojan_Win32_IcedId_DBI_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 50 8d 44 24 0c 53 6a 01 53 53 50 ff 15 ?? ?? ?? ?? 85 c0 75 3a 6a 08 6a 01 53 8d 4c 24 18 53 51 ff 15 90 1b 00 85 c0 75 25 } //1
		$a_81_1 = {57 38 6d 57 7a 57 53 58 36 5a 76 77 31 6d 47 } //1 W8mWzWSX6Zvw1mG
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}