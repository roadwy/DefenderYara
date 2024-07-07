
rule Trojan_Win32_BHO_Y{
	meta:
		description = "Trojan:Win32/BHO.Y,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_02_1 = {61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 08 00 00 00 68 00 72 00 65 00 66 00 00 00 00 00 ff ff ff ff 0c 00 00 00 70 61 67 65 61 64 2f 69 63 6c 6b 3f 00 00 00 00 ff ff ff ff 90 01 02 00 00 68 74 74 70 3a 2f 2f 70 61 67 65 61 64 32 2e 67 6f 6f 67 6c 65 73 79 6e 64 69 63 61 74 69 6f 6e 73 73 69 74 65 2e 63 6f 6d 2f 70 61 67 65 61 64 2f 69 63 6c 6b 3f 73 61 3d 6c 26 61 69 3d 42 38 64 58 73 65 90 00 } //10
		$a_00_2 = {49 45 28 41 4c 28 22 25 73 22 2c } //1 IE(AL("%s",
	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1) >=21
 
}