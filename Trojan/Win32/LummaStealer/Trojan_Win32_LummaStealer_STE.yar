
rule Trojan_Win32_LummaStealer_STE{
	meta:
		description = "Trojan:Win32/LummaStealer.STE,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 49 44 41 54 } //1
		$a_01_1 = {0f b6 d2 c1 e1 05 81 e1 e0 7f 00 00 31 d1 0f b7 94 4e 72 92 02 00 89 c7 81 e7 ff 7f 00 00 66 89 94 7e 72 92 01 00 89 da 42 66 89 84 4e 72 92 02 00 45 } //1
		$a_03_2 = {ae 42 60 82 c7 ?? ?? ?? 49 45 4e 44 } //1
		$a_03_3 = {80 38 ef 75 ?? 80 78 01 bb 75 ?? 80 78 02 bf } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}