
rule Trojan_Win32_Carberp_BX_bit{
	meta:
		description = "Trojan:Win32/Carberp.BX!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 4d 00 70 00 36 00 63 00 33 00 59 00 67 00 75 00 6b 00 78 00 32 00 39 00 47 00 62 00 44 00 6b 00 5f 00 65 00 78 00 69 00 74 00 } //2 Global\Mp6c3Ygukx29GbDk_exit
		$a_03_1 = {77 69 6e 00 2c 73 65 72 76 65 72 00 2c 78 36 34 [0-04] 2c 78 38 36 00 } //2
		$a_01_2 = {70 00 72 00 6f 00 64 00 75 00 70 00 64 00 2e 00 65 00 78 00 65 00 } //1 produpd.exe
		$a_01_3 = {6d 00 6f 00 6e 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 monhost.exe
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}