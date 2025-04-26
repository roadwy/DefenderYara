
rule Trojan_Win32_Vflooder_MSR{
	meta:
		description = "Trojan:Win32/Vflooder!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {56 4d 47 72 61 62 } //1 VMGrab
		$a_01_1 = {61 36 32 38 31 32 37 39 2e 79 6f 6c 6f 78 2e 6e 65 74 } //1 a6281279.yolox.net
		$a_01_2 = {76 74 61 70 69 2f 76 32 2f 66 69 6c 65 2f 73 63 61 6e } //1 vtapi/v2/file/scan
		$a_01_3 = {51 6b 6b 62 61 6c } //1 Qkkbal
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}