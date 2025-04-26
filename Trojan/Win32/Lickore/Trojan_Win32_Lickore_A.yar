
rule Trojan_Win32_Lickore_A{
	meta:
		description = "Trojan:Win32/Lickore.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 07 00 06 00 00 "
		
	strings :
		$a_00_0 = {65 6e 6a 6f 79 2d 66 69 6e 64 2e 63 6f 6d 2f 69 6e 64 65 78 2e 68 74 6d 6c 3f 61 63 3d } //1 enjoy-find.com/index.html?ac=
		$a_00_1 = {63 6c 69 63 6b 2e 6c 69 6e 6b 70 72 69 63 65 2e 63 6f 6d 2f 63 6c 69 63 6b 2e 70 68 70 3f 6d 3d } //1 click.linkprice.com/click.php?m=
		$a_00_2 = {69 6c 69 6b 65 63 6c 69 63 6b 2e 63 6f 6d 2f 74 72 61 63 6b } //1 ilikeclick.com/track
		$a_03_3 = {85 c9 74 19 8b 06 83 78 f4 00 7c 11 51 50 e8 ?? ?? 01 00 83 c4 08 85 c0 74 03 2b 06 c3 } //2
		$a_01_4 = {8b 08 8b 11 50 8b 42 04 ff d0 8b 5c 24 14 83 7b f4 00 0f 8c d5 00 00 00 } //2
		$a_03_5 = {8d 70 10 83 c4 04 89 74 24 14 c6 84 24 ?? ?? ?? ?? 07 83 7e f4 00 0f 8c 94 12 00 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*2+(#a_01_4  & 1)*2+(#a_03_5  & 1)*2) >=7
 
}