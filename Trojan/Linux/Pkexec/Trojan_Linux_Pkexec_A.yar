
rule Trojan_Linux_Pkexec_A{
	meta:
		description = "Trojan:Linux/Pkexec.A,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 00 63 00 6f 00 6e 00 76 00 5f 00 70 00 61 00 74 00 68 00 3d 00 } //10 gconv_path=
		$a_00_1 = {64 00 67 00 63 00 6f 00 6e 00 76 00 5f 00 70 00 61 00 74 00 68 00 3d 00 } //-10 dgconv_path=
		$a_00_2 = {64 00 61 00 74 00 61 00 2f 00 79 00 6f 00 63 00 74 00 6f 00 2f 00 6b 00 65 00 79 00 2d 00 63 00 6f 00 6d 00 73 00 2d 00 61 00 70 00 70 00 73 00 } //-10 data/yocto/key-coms-apps
		$a_00_3 = {6b 00 69 00 72 00 6b 00 73 00 74 00 6f 00 6e 00 65 00 2d 00 62 00 73 00 70 00 2f 00 62 00 75 00 69 00 6c 00 64 00 5f 00 6d 00 67 00 65 00 61 00 } //-10 kirkstone-bsp/build_mgea
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*-10+(#a_00_2  & 1)*-10+(#a_00_3  & 1)*-10) >=10
 
}