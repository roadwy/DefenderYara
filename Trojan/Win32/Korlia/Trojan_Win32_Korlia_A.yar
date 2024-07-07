
rule Trojan_Win32_Korlia_A{
	meta:
		description = "Trojan:Win32/Korlia.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {f2 ae f7 d1 49 8d 7c 90 01 02 8b c1 c7 05 90 01 04 00 00 00 00 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 eb 90 00 } //1
		$a_00_1 = {62 69 73 6f 6e 61 6c } //1 bisonal
		$a_00_2 = {6b 7e 73 76 7e 31 4f 7e 6c 6c 76 71 78 58 7e 6c 31 71 7a 6b } //1 k~sv~1O~llvqxX~l1qzk
		$a_00_3 = {77 6b 6b 6f 25 30 30 79 6a 71 7b 31 7c 72 7c 31 70 6d } //1 wkko%00yjq{1|r|1pm
		$a_00_4 = {53 76 63 48 6f 73 74 44 4c 4c 2e 64 6c 6c } //1 SvcHostDLL.dll
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}