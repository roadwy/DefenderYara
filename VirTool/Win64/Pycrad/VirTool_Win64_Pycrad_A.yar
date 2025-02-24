
rule VirTool_Win64_Pycrad_A{
	meta:
		description = "VirTool:Win64/Pycrad.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 79 72 61 6d 69 64 5f 6d 6f 64 75 6c 65 } //1 pyramid_module
		$a_01_1 = {65 6e 63 6f 64 65 5f 65 6e 63 72 79 70 74 5f 75 72 6c } //1 encode_encrypt_url
		$a_01_2 = {70 79 72 61 6d 69 64 5f 70 61 73 73 } //1 pyramid_pass
		$a_01_3 = {50 52 4f 54 4f 43 4f 4c 5f 54 4c 53 5f 43 4c 49 45 4e 54 } //1 PROTOCOL_TLS_CLIENT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}