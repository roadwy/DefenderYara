
rule Trojan_Win32_DCRat_ASFU_MTB{
	meta:
		description = "Trojan:Win32/DCRat.ASFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 08 03 4d fc 88 01 8b 55 08 03 55 fc 0f b6 02 35 90 01 04 8b 4d 08 03 4d fc 88 01 e9 90 00 } //4
		$a_01_1 = {58 69 41 6e 41 39 31 6b 6c 61 4b } //1 XiAnA91klaK
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}