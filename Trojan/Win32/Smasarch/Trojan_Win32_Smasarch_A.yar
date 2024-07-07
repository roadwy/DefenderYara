
rule Trojan_Win32_Smasarch_A{
	meta:
		description = "Trojan:Win32/Smasarch.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {73 6d 73 73 74 61 74 75 73 2e 63 6f 6d 2f 73 6d 73 2f 69 73 76 61 6c 69 64 90 01 01 2e 70 68 70 3f 63 6f 64 65 3d 90 01 03 26 63 6f 75 6e 74 72 79 3d 90 01 02 26 70 72 3d 90 02 20 26 61 66 3d 90 00 } //1
		$a_00_1 = {73 68 61 72 65 77 61 72 65 2e 70 72 6f } //1 shareware.pro
		$a_00_2 = {2f 42 41 4e 4e 45 52 } //1 /BANNER
		$a_00_3 = {55 52 4c 20 50 61 72 74 73 20 45 72 72 6f 72 } //1 URL Parts Error
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}