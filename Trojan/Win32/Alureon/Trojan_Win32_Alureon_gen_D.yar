
rule Trojan_Win32_Alureon_gen_D{
	meta:
		description = "Trojan:Win32/Alureon.gen!D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_00_0 = {eb b9 81 7d d4 96 00 00 00 77 06 83 7d d4 32 73 01 cc } //1
		$a_00_1 = {eb b9 81 7d d0 96 00 00 00 77 06 83 7d d0 32 73 01 cc } //1
		$a_00_2 = {9c 8f 45 fc 6a 00 6a 64 e8 00 00 00 00 58 83 c0 09 50 ff 65 e0 cc 85 c0 75 fb 64 a1 30 00 00 00 85 c0 78 5c } //1
		$a_02_3 = {9c 8f 45 fc 81 65 fc 00 01 00 00 74 01 cc 8b 55 e4 52 68 90 01 04 e8 90 01 02 ff ff 83 c4 08 89 45 e0 6a 00 6a 64 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}