
rule Trojan_Win32_TrickbotCrypt_SS_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 68 00 30 00 00 53 6a 00 ff d5 8b 77 ?? 8b d8 8b 44 24 ?? 33 c9 89 44 24 ?? 8b d3 33 c0 89 5c 24 ?? 40 89 44 24 ?? 85 f6 74 ?? 8b 6c 24 ?? 8b 5c 24 ?? 23 e8 4e 85 ed 74 } //1
		$a_03_1 = {8b c7 2b 44 24 ?? 3b c8 73 ?? 83 f9 3c 72 ?? 83 f9 3e 76 ?? c6 02 00 eb ?? 8a 03 88 02 41 43 42 85 f6 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}