
rule Trojan_Win32_Dridex_FT_MTB{
	meta:
		description = "Trojan:Win32/Dridex.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 66 8b 18 8b 44 24 2c 89 74 24 30 be 90 01 04 29 c6 89 74 24 28 8b 44 24 1c 35 b5 d4 2b 6e 8b 74 24 18 89 74 24 3c 89 44 24 38 66 39 fb 90 00 } //10
		$a_80_1 = {31 74 68 65 69 64 65 6e 74 69 66 69 65 72 31 31 38 32 30 31 36 70 61 73 73 77 6f 72 64 } //1theidentifier1182016password  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}