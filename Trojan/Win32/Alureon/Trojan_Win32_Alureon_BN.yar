
rule Trojan_Win32_Alureon_BN{
	meta:
		description = "Trojan:Win32/Alureon.BN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 1d 57 8d 45 f8 50 68 00 d2 00 00 68 ?? ?? ?? ?? 56 ff 15 } //1
		$a_01_1 = {c7 45 e4 54 00 00 00 c7 45 c4 ab 00 00 00 8b 4d c4 83 c1 01 8b 45 e4 99 f7 f9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}