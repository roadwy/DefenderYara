
rule Trojan_AndroidOS_Zniu_C_MTB{
	meta:
		description = "Trojan:AndroidOS/Zniu.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_00_0 = {4a 61 76 61 5f 63 6f 6d 5f 73 64 6b 79 5f 6c 79 72 5f 7a 6e 69 75 5f 48 75 6e 74 52 65 63 65 69 76 65 5f 6e 61 74 69 76 65 48 61 6e 64 6c 65 52 65 63 65 69 76 65 } //2 Java_com_sdky_lyr_zniu_HuntReceive_nativeHandleReceive
		$a_00_1 = {4a 61 76 61 5f 63 6f 6d 5f 73 64 6b 79 5f 6c 79 72 5f 7a 6e 69 75 5f 48 75 6e 74 55 74 69 6c 73 5f 6e 61 74 69 76 65 50 65 72 70 61 72 65 } //2 Java_com_sdky_lyr_zniu_HuntUtils_nativePerpare
		$a_00_2 = {6c 69 62 68 75 6e 74 2e 73 6f } //1 libhunt.so
		$a_00_3 = {25 73 6c 6f 63 61 6c 2e 7a 69 75 } //1 %slocal.ziu
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=6
 
}