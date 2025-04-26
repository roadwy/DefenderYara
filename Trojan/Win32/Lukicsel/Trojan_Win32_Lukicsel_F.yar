
rule Trojan_Win32_Lukicsel_F{
	meta:
		description = "Trojan:Win32/Lukicsel.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 57 69 6e 6c 6f 67 6f 6e 4c 6f 67 6f 66 66 45 76 65 6e 74 00 57 69 6e 6c 6f 67 6f 6e 53 74 61 72 74 75 70 45 76 65 6e 74 00 } //1 圀湩潬潧䱮杯景䕦敶瑮圀湩潬潧卮慴瑲灵癅湥t
		$a_03_1 = {8d 45 08 e8 ?? ?? ?? ?? 32 06 88 07 46 47 4b 75 ef } //1
		$a_03_2 = {6a 00 6a 02 ff 15 ?? ?? ?? ?? 8b d8 85 db 75 ?? e8 ?? ?? ?? ?? 83 f8 02 75 05 e8 ?? ?? ?? ?? 68 e8 03 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}