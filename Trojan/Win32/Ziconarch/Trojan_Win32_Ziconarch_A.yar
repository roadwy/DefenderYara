
rule Trojan_Win32_Ziconarch_A{
	meta:
		description = "Trojan:Win32/Ziconarch.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_11_0 = {6f 67 69 6e 63 6f 69 6e 2e 72 75 01 } //1 杯湩潣湩爮ŵ
		$a_73_1 = {63 6f 6e 64 63 6f 69 6e 2e 72 75 01 00 10 11 5a 69 } //3328
		$a_69_2 = {5f 6f 72 69 67 69 6e 61 6c 01 00 1c 01 2f 7a 69 70 63 6f 69 6e 2e 72 75 2f 61 72 63 68 72 66 2f 3f 61 72 63 68 72 65 66 3d 01 00 2e 01 53 65 6e 64 69 6e 67 20 53 4d 53 20 79 6f 75 20 61 67 72 65 65 20 77 69 74 68 20 74 68 65 20 75 73 65 72 20 61 67 72 65 65 6d 65 6e 74 2e 00 00 5d 04 00 00 ca ff 02 80 5c 22 00 00 cb ff 02 80 00 00 } //17264
		$a_00_3 = {0c 00 ac 21 5a 69 70 70 } //1
		$a_68_4 = {41 00 00 02 40 05 82 70 00 04 00 67 16 00 00 da 7f e4 e9 80 45 37 b5 1b 38 01 ff 6a 09 e1 01 01 20 bb 59 31 3b 80 10 00 00 99 f4 29 25 a2 c2 62 cf 4c 90 be 16 00 10 00 80 5d 04 00 00 cb ff 02 80 5c 22 00 00 cc ff 02 80 00 00 01 00 27 00 0c 00 c8 21 42 61 6e 63 6f 73 2e 41 4a 4c 00 00 05 40 05 82 } //29281
	condition:
		((#a_11_0  & 1)*1+(#a_73_1  & 1)*3328+(#a_69_2  & 1)*17264+(#a_00_3  & 1)*1+(#a_68_4  & 1)*29281) >=5
 
}