
rule Trojan_Win32_Tinba_PDSK_MTB{
	meta:
		description = "Trojan:Win32/Tinba.PDSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {30 04 39 47 3b fb 7c 90 09 0b 00 e8 90 01 04 8b 8d 90 01 02 ff ff 90 00 } //1
		$a_02_1 = {69 c0 fd 43 03 00 a3 90 01 04 81 05 90 01 04 c3 9e 26 00 81 3d 90 01 04 a5 02 00 00 8b 35 90 01 04 75 90 09 05 00 a1 90 00 } //1
		$a_02_2 = {0f af df 03 c8 89 8d 90 01 02 ff ff 8a 09 03 de 32 cb 88 8c 35 90 01 02 ff ff 90 09 0c 00 8b 8d 90 01 02 ff ff 89 9d 90 01 02 ff ff 90 00 } //2
		$a_00_3 = {8a 44 24 4b 04 f1 29 f9 88 84 24 8d 00 00 00 89 4c 24 58 8b 4c 24 74 8a 84 24 87 00 00 00 34 45 85 c9 8b 4c 24 58 8b 7c 24 3c 0f 44 f9 89 7c 24 7c } //2
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*2+(#a_00_3  & 1)*2) >=2
 
}