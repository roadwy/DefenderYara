
rule Trojan_AndroidOS_Thamera_WT{
	meta:
		description = "Trojan:AndroidOS/Thamera.WT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 57 78 73 62 33 63 67 63 47 56 79 62 57 6c 7a 63 32 6c 76 62 69 42 30 62 79 42 6a 62 32 35 30 61 57 35 31 5a 51 3d 3d } //1 QWxsb3cgcGVybWlzc2lvbiB0byBjb250aW51ZQ==
		$a_01_1 = {51 56 42 51 58 30 35 46 56 77 3d 3d } //1 QVBQX05FVw==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}