
rule Trojan_AndroidOS_Hiddad_R{
	meta:
		description = "Trojan:AndroidOS/Hiddad.R,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6c 61 73 73 65 73 5f 64 65 78 5f 64 69 67 65 73 74 } //1 classes_dex_digest
		$a_01_1 = {49 73 20 79 6f 75 72 20 69 6e 74 65 6e 74 20 73 70 65 6c 6c 65 64 20 63 6f 72 72 65 63 74 6c 79 } //1 Is your intent spelled correctly
		$a_01_2 = {63 6f 6d 2e 61 71 70 6c 61 79 2e 70 72 6f 78 79 2e 69 6d 70 6c 2e 50 72 6f 78 79 4d 61 6e 61 67 65 72 } //1 com.aqplay.proxy.impl.ProxyManager
		$a_01_3 = {47 30 30 46 78 66 42 4f 62 67 66 67 54 76 7a 67 61 41 76 61 6c 75 42 58 54 6e 76 75 30 4e 32 74 35 4b 47 30 75 62 51 43 32 34 64 32 64 54 72 72 } //1 G00FxfBObgfgTvzgaAvaluBXTnvu0N2t5KG0ubQC24d2dTrr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}