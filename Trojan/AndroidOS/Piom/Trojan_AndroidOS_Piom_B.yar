
rule Trojan_AndroidOS_Piom_B{
	meta:
		description = "Trojan:AndroidOS/Piom.B,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {68 61 73 41 67 72 65 65 64 4c 61 77 } //1 hasAgreedLaw
		$a_00_1 = {2f 2e 77 6e 62 72 6f 77 73 65 72 } //1 /.wnbrowser
		$a_00_2 = {43 68 65 63 6b 46 6c 61 67 45 61 63 68 44 61 79 5f } //1 CheckFlagEachDay_
		$a_00_3 = {2f 46 69 6c 65 63 68 6f 6f 73 65 72 41 63 74 69 76 69 74 79 3b } //1 /FilechooserActivity;
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}