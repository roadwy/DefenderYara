
rule Trojan_AndroidOS_Plangton_RT{
	meta:
		description = "Trojan:AndroidOS/Plangton.RT,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 65 72 68 61 6e 64 20 73 65 72 76 69 63 65 20 77 61 73 20 73 74 61 72 74 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Apperhand service was started successfully
		$a_01_1 = {43 52 6f 51 41 6c 56 47 53 31 6b 65 47 56 6f 45 48 67 52 4c 45 42 6f 4f 47 52 64 4c 45 55 45 } //1 CRoQAlVGS1keGVoEHgRLEBoOGRdLEUE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}