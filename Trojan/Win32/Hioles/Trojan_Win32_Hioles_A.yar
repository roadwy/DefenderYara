
rule Trojan_Win32_Hioles_A{
	meta:
		description = "Trojan:Win32/Hioles.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c2 61 8b 45 08 03 45 fc 88 10 eb ?? 8b 4d 08 c6 41 09 2e 8b 55 08 c6 42 0a 64 8b 45 08 c6 40 0b 6c 8b 4d 08 c6 41 0c 6c 8b 55 08 c6 42 0d 00 } //1
		$a_03_1 = {6a 40 6a 00 6a 01 8d 4d f4 51 6a 00 6a 00 6a 00 8d 55 ec 52 8b 45 f8 50 8b 4d e8 51 ff 55 f0 85 c0 7c ?? 6a 00 6a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}