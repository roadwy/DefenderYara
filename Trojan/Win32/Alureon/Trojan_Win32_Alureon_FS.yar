
rule Trojan_Win32_Alureon_FS{
	meta:
		description = "Trojan:Win32/Alureon.FS,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_11_0 = {00 00 00 00 59 81 e1 00 f0 ff ff 66 81 39 4d 5a 01 } //1
		$a_5c_1 = {5c } //19456 \
		$a_00_3 = {4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 25 00 75 00 01 00 12 01 46 00 49 00 4c 00 45 00 } //71
	condition:
		((#a_11_0  & 1)*1+(#a_5c_1  & 1)*19456+(#a_00_3  & 1)*71) >=3
 
}