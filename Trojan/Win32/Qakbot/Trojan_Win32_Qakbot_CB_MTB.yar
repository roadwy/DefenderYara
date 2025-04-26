
rule Trojan_Win32_Qakbot_CB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_00_0 = {89 d9 56 29 cb 8b 46 08 03 46 10 01 4e 10 89 c6 89 ca c1 e9 02 fc } //10
		$a_81_1 = {54 64 72 68 79 6d 77 34 6f 69 35 6a } //1 Tdrhymw4oi5j
		$a_81_2 = {35 35 36 36 36 6e 30 6a 75 6d 62 34 39 35 36 6a 38 68 79 75 62 74 6e 76 65 6a 72 74 67 65 6f 72 68 77 72 79 39 35 38 75 36 6a 39 79 35 } //1 55666n0jumb4956j8hyubtnvejrtgeorhwry958u6j9y5
	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_Win32_Qakbot_CB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {48 4a 42 55 46 53 49 5a 45 59 55 56 } //1 HJBUFSIZEYUV
		$a_01_1 = {48 63 6f 70 79 5f 6d 61 72 6b 65 72 73 5f 65 78 65 63 75 74 65 } //1 Hcopy_markers_execute
		$a_01_2 = {48 69 6e 69 74 5f 31 70 61 73 73 5f 71 75 61 6e 74 69 7a 65 72 } //1 Hinit_1pass_quantizer
		$a_01_3 = {48 70 65 67 5f 43 72 65 61 74 65 44 65 63 6f 6d 70 72 65 73 73 } //1 Hpeg_CreateDecompress
		$a_01_4 = {48 70 65 67 5f 68 75 66 66 5f 64 65 63 6f 64 65 } //1 Hpeg_huff_decode
		$a_01_5 = {48 70 65 67 5f 6d 61 6b 65 5f 63 5f 64 65 72 69 76 65 64 5f 74 62 6c } //1 Hpeg_make_c_derived_tbl
		$a_01_6 = {48 73 69 6d 64 5f 63 61 6e 5f 63 6f 6e 76 73 61 6d 70 5f 66 6c 6f 61 74 } //1 Hsimd_can_convsamp_float
		$a_01_7 = {48 73 69 6d 64 5f 63 61 6e 5f 68 32 76 32 5f 66 61 6e 63 79 5f 75 70 73 61 6d 70 6c 65 } //1 Hsimd_can_h2v2_fancy_upsample
		$a_01_8 = {48 6a 44 65 63 6f 6d 70 72 65 73 73 54 6f 59 55 56 } //1 HjDecompressToYUV
		$a_01_9 = {48 70 65 67 5f 6f 70 65 6e 5f 62 61 63 6b 69 6e 67 5f 73 74 6f 72 65 } //1 Hpeg_open_backing_store
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}