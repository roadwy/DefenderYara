
rule Trojan_Win32_Multsarch_U{
	meta:
		description = "Trojan:Win32/Multsarch.U,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_02_0 = {68 74 74 70 3a 2f 2f 67 77 2e 6e 65 74 6c 69 6e 6b 69 6e 76 65 73 74 2e 63 6f 6d 2f 63 68 65 63 6b 63 6f 64 65 2e 70 68 70 3f 67 77 3d [0-02] 26 64 6f 63 75 6d 65 6e 74 3d [0-20] 26 63 6f 75 6e 74 72 79 3d 65 73 26 63 6f 64 65 3d } //10
		$a_00_1 = {64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 } //10 download_quiet
		$a_00_2 = {45 73 74 61 20 61 20 70 75 6e 74 6f 20 64 65 20 75 74 69 6c 69 7a 61 72 20 75 6e 61 20 64 65 73 63 61 72 67 61 20 70 72 65 6d 69 75 6d 2c 20 73 75 20 61 79 75 64 61 20 6e 6f 73 20 70 65 72 6d 69 74 65 20 67 61 72 61 6e 74 69 7a 61 72 20 75 6e 20 6d 65 6a 6f 72 20 73 65 72 76 69 63 69 6f 2e } //1 Esta a punto de utilizar una descarga premium, su ayuda nos permite garantizar un mejor servicio.
		$a_02_3 = {68 74 74 70 3a 2f 2f 65 6c 70 61 72 74 69 64 6f 2e 73 6f 66 74 32 30 31 32 2e 6e 65 74 2f 65 73 2f 63 6f 6e 66 69 67 5f [0-04] 2e 78 6d 6c } //1
		$a_00_4 = {46 6c 61 73 68 20 50 6c 61 79 65 72 20 31 30 2e 30 2e 33 32 2e 31 38 20 28 4e 6f 6e 2d 49 45 29 } //1 Flash Player 10.0.32.18 (Non-IE)
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=23
 
}