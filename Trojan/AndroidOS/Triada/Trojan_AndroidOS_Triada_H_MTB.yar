
rule Trojan_AndroidOS_Triada_H_MTB{
	meta:
		description = "Trojan:AndroidOS/Triada.H!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {6f 73 2e 63 6f 6e 66 69 67 2e 70 70 67 6c 2e 62 74 63 6f 72 65 2e 64 65 76 69 63 65 6b 65 79 } //1 os.config.ppgl.btcore.devicekey
		$a_01_1 = {6f 73 2e 63 6f 6e 66 69 67 2e 6f 70 70 2e 62 75 69 6c 64 2e 73 74 61 74 75 73 } //1 os.config.opp.build.status
		$a_01_2 = {76 65 72 73 69 6f 6e 5f 65 78 5f 63 6f 6e 66 69 67 2e 64 61 74 } //1 version_ex_config.dat
		$a_01_3 = {6f 73 2e 63 6f 6e 66 69 67 2e 6f 70 70 2e 62 75 69 6c 64 2e 6d 6f 64 65 6c } //1 os.config.opp.build.model
		$a_01_4 = {63 6f 6d 2e 68 77 73 65 6e 2e 61 62 63 2e 53 44 4b } //1 com.hwsen.abc.SDK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}