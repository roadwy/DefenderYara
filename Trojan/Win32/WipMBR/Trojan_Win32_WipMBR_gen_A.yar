
rule Trojan_Win32_WipMBR_gen_A{
	meta:
		description = "Trojan:Win32/WipMBR.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 83 f9 02 0f 8c 90 01 04 8b 57 04 0f b7 02 83 e8 30 0f 84 90 00 } //2
		$a_01_1 = {2f 00 61 00 6a 00 61 00 78 00 5f 00 6d 00 6f 00 64 00 61 00 6c 00 2f 00 6d 00 6f 00 64 00 61 00 6c 00 2f 00 64 00 61 00 74 00 61 00 2e 00 61 00 73 00 70 00 } //1 /ajax_modal/modal/data.asp
		$a_03_2 = {8b d6 83 e2 03 8a 82 90 01 04 32 04 0e 6a 00 8d 55 90 01 01 52 88 45 90 01 01 6a 01 8d 45 90 01 01 50 57 90 00 } //2
		$a_01_3 = {15 af 52 f0 a0 ff ca 10 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1) >=3
 
}