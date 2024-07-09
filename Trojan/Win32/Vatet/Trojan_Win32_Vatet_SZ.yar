
rule Trojan_Win32_Vatet_SZ{
	meta:
		description = "Trojan:Win32/Vatet.SZ,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_03_1 = {74 02 eb ea ?? ff ?? e8 d4 ff ff ff 90 09 22 00 eb 27 ?? 8b ?? 83 ?? 04 8b ?? 31 ?? 83 ?? 04 ?? 8b ?? 31 ?? 89 ?? 31 ?? 83 ?? 04 83 ?? 04 31 } //100
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*100) >=101
 
}