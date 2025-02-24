
rule Trojan_Win32_LummaStealer_MEL_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.MEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c9 8b 85 e0 ef ff ff 30 0c 10 8b 95 ec ef ff ff 83 c7 04 42 } //2
		$a_01_1 = {64 61 74 61 62 61 73 65 5c 77 69 72 65 66 72 5c 78 36 34 5c 48 54 54 50 5c 49 6e 74 65 72 6f 2e 70 64 62 } //1 database\wirefr\x64\HTTP\Intero.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}