
rule Trojan_Win32_Chindo_SP_MSR{
	meta:
		description = "Trojan:Win32/Chindo.SP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 4d 61 69 6e 5c 46 65 61 74 75 72 65 43 6f 6e 74 72 6f 6c 5c 46 45 41 54 55 52 45 5f 42 52 4f 57 53 45 52 5f 45 4d 55 4c 41 54 49 4f 4e } //1 Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION
		$a_01_1 = {63 6f 6e 66 69 67 2e 6d 79 6c 6f 67 6c 69 73 74 2e 74 6f 70 } //1 config.myloglist.top
		$a_01_2 = {5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 44 00 61 00 74 00 61 00 5c 00 59 00 69 00 59 00 61 00 5a 00 69 00 70 00 5c 00 } //2 \Application Data\YiYaZip\
		$a_01_3 = {4d 7a 59 77 56 48 4a 68 65 53 35 6c 65 47 55 3d } //1 MzYwVHJheS5leGU=
		$a_01_4 = {59 69 43 6f 6d 70 72 65 73 73 5f 55 70 64 61 74 65 5f 4d 75 74 65 78 } //2 YiCompress_Update_Mutex
		$a_01_5 = {5c 59 69 43 6f 6d 70 72 65 73 73 5c 59 69 7a 2e 63 6f 6e 66 69 67 } //2 \YiCompress\Yiz.config
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=3
 
}