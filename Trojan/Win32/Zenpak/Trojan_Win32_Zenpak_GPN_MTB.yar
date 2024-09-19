
rule Trojan_Win32_Zenpak_GPN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 77 74 72 34 5f 65 37 62 68 38 5f 39 72 37 74 79 38 39 5f 34 79 35 31 74 35 68 31 } //2 ewtr4_e7bh8_9r7ty89_4y51t5h1
		$a_01_1 = {72 65 70 32 35 38 33 6c 61 63 65 } //1 rep2583lace
		$a_01_2 = {72 65 70 32 30 30 34 61 63 65 } //1 rep2004ace
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}