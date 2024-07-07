
rule Trojan_Win32_CryptBot_LK_MTB{
	meta:
		description = "Trojan:Win32/CryptBot.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 08 88 44 96 01 8b c1 88 0c 96 c1 e8 18 c1 e9 10 88 44 96 03 88 4c 96 02 } //1
		$a_01_1 = {8b 4d 08 8d 14 90 8b c1 88 0a c1 e8 08 88 42 01 8b c1 c1 e8 18 c1 e9 10 88 42 03 88 4a 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}