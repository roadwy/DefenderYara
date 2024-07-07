
rule Trojan_AndroidOS_Clipper_A{
	meta:
		description = "Trojan:AndroidOS/Clipper.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6c 69 70 70 65 72 2f 61 62 63 63 68 61 6e 6e 65 6c 6d 63 2f 72 75 2f 63 6c 69 70 70 65 72 72 65 62 6f 72 6e } //1 Lclipper/abcchannelmc/ru/clipperreborn
		$a_00_1 = {61 74 74 61 63 68 2e 70 68 70 3f 6c 6f 67 26 77 61 6c 6c 65 74 3d } //1 attach.php?log&wallet=
		$a_00_2 = {47 65 74 74 65 64 20 77 61 6c 6c 65 74 } //1 Getted wallet
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}