
rule Trojan_Win32_Strysx_A{
	meta:
		description = "Trojan:Win32/Strysx.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 ff 00 00 00 6a 06 6a 03 68 ?? da 40 00 ff 15 ?? ?? 40 00 83 f8 ff a3 ?? ?? 41 00 74 6c 53 50 } //1
		$a_02_1 = {8d 7c 24 10 e8 ?? ff ff ff 8d 44 24 18 50 8b cf e8 ?? fe ff ff 8b 70 04 59 6a 00 8d 44 24 10 50 56 e8 ?? ?? 00 00 59 40 50 56 ff 35 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}