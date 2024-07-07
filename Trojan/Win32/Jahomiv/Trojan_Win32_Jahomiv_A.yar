
rule Trojan_Win32_Jahomiv_A{
	meta:
		description = "Trojan:Win32/Jahomiv.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {56 8d 34 01 e8 90 01 01 ff ff ff 30 06 90 00 } //1
		$a_01_1 = {0f be 04 02 03 07 03 c6 25 ff 00 00 00 8b f0 8a 07 88 45 ff } //1
		$a_01_2 = {c1 e8 10 88 06 46 8b c3 c1 e8 08 88 06 46 88 1e 46 33 db 88 5d 0b } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}