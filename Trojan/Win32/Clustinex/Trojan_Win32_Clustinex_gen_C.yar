
rule Trojan_Win32_Clustinex_gen_C{
	meta:
		description = "Trojan:Win32/Clustinex.gen!C,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {29 00 63 00 3a 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 67 00 38 00 32 00 38 00 61 00 66 00 } //1 )c:\temp\g828af
		$a_01_1 = {39 64 32 66 35 34 61 38 2d 37 64 34 32 2d 34 30 36 35 2d 61 65 31 31 2d 64 35 36 39 36 36 66 66 32 66 63 62 } //1 9d2f54a8-7d42-4065-ae11-d56966ff2fcb
		$a_01_2 = {3b 00 63 00 3a 00 5c 00 74 00 65 00 6d 00 70 00 5c 00 67 00 38 00 32 00 38 00 61 00 66 00 } //1 ;c:\temp\g828af
		$a_01_3 = {5c 21 5c 23 5c 25 5c 27 5c 29 5c 2b 5c 2d 5c 2f 5c 31 5c 33 5c 35 5c 37 5c 39 5c 3b 5c 3d 5c 3f 5c 61 5c 63 5c 65 5c 67 5c 69 5c 6b 5c 6d 5c 6f 5c 2a } //1 \!\#\%\'\)\+\-\/\1\3\5\7\9\;\=\?\a\c\e\g\i\k\m\o\*
		$a_01_4 = {70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 63 6f 6d 6d 6f 6e 20 66 69 6c 65 73 5c 73 79 73 74 65 6d 5c 6f 6c 65 20 64 62 5c } //1 program files\common files\system\ole db\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}