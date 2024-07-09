
rule Trojan_Win32_Aptdrop_RU{
	meta:
		description = "Trojan:Win32/Aptdrop.RU,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {51 ff 33 58 83 c3 04 f7 d8 f8 83 d8 26 8d 40 ff 29 f8 8d 38 [0-08] f8 83 d9 fc 8d 52 04 81 fa 88 06 00 00 75 } //1
		$a_00_1 = {51 ff 33 58 83 c3 04 f7 d8 83 e8 26 83 e8 02 83 e8 ff 29 f8 50 5f c7 01 00 00 00 00 01 01 83 e9 fc 83 c2 04 81 fa 88 06 00 00 75 d5 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}