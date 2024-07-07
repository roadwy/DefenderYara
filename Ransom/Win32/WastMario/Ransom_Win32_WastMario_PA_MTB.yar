
rule Ransom_Win32_WastMario_PA_MTB{
	meta:
		description = "Ransom:Win32/WastMario.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_02_0 = {5c 55 73 65 72 73 5c 72 6f 69 6c 65 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 57 61 73 74 65 64 42 69 74 5c 90 02 10 5c 57 61 73 74 65 64 42 69 74 2e 70 64 62 90 00 } //4
		$a_00_1 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 57 61 73 74 65 64 42 69 74 5c 57 61 73 74 65 64 2e 62 6d 70 } //2 \Documents\WastedBit\Wasted.bmp
		$a_00_2 = {59 6f 75 27 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 6c 6f 63 6b 65 64 20 62 79 20 4d 61 72 69 6f } //2 You'r files has been locked by Mario
		$a_00_3 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 57 61 73 74 65 64 42 69 74 5c 6d 61 72 69 6f 2e 77 61 76 } //2 \Documents\WastedBit\mario.wav
		$a_00_4 = {73 72 76 2d 66 69 6c 65 37 2e 67 6f 66 69 6c 65 2e 69 6f 2f 64 6f 77 6e 6c 6f 61 64 2f 36 4d 41 51 51 6c 2f 4d 61 72 69 6f 2d 50 69 78 54 65 6c 6c 65 72 2e 70 6e 67 } //2 srv-file7.gofile.io/download/6MAQQl/Mario-PixTeller.png
		$a_00_5 = {40 52 65 61 64 6d 65 2e 74 78 74 } //1 @Readme.txt
		$a_00_6 = {2e 77 61 73 74 65 64 } //1 .wasted
	condition:
		((#a_02_0  & 1)*4+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*2+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=8
 
}