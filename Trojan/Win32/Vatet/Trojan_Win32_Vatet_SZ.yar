
rule Trojan_Win32_Vatet_SZ{
	meta:
		description = "Trojan:Win32/Vatet.SZ,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {74 02 eb ea 90 01 01 ff 90 01 01 e8 d4 ff ff ff 90 09 22 00 eb 27 90 01 01 8b 90 01 01 83 90 01 01 04 8b 90 01 01 31 90 01 01 83 90 01 01 04 90 01 01 8b 90 01 01 31 90 01 01 89 90 01 01 31 90 01 01 83 90 01 01 04 83 90 01 01 04 31 90 00 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}