
rule Trojan_Win32_ACRStealer_AB_MTB{
	meta:
		description = "Trojan:Win32/ACRStealer.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 26 31 c9 41 39 3c 0e 74 13 50 32 24 0e 88 64 15 00 58 41 42 38 c1 76 ec 01 ce eb e3 } //6
		$a_81_1 = {72 61 77 68 69 64 65 } //1 rawhide
	condition:
		((#a_01_0  & 1)*6+(#a_81_1  & 1)*1) >=7
 
}