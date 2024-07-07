
rule Trojan_Win32_DCRat_MQ_MTB{
	meta:
		description = "Trojan:Win32/DCRat.MQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 0f b0 01 eb 30 85 ff 74 03 c6 07 01 32 c0 eb 25 } //5
		$a_00_1 = {2e 76 62 65 } //5 .vbe
		$a_01_2 = {44 00 61 00 72 00 6b 00 43 00 72 00 79 00 73 00 74 00 61 00 6c 00 20 00 52 00 41 00 54 00 } //1 DarkCrystal RAT
		$a_01_3 = {44 00 43 00 72 00 61 00 74 00 } //1 DCrat
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=11
 
}