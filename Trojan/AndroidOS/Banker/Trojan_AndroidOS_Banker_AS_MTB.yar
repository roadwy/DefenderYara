
rule Trojan_AndroidOS_Banker_AS_MTB{
	meta:
		description = "Trojan:AndroidOS/Banker.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {67 6f 76 46 69 72 65 77 61 6c 6c 2e 61 70 6b } //1 govFirewall.apk
		$a_01_1 = {4c 63 6f 6d 2f 79 63 2f 6d 79 6f 70 65 6e 61 70 70 } //1 Lcom/yc/myopenapp
		$a_01_2 = {63 6f 6d 2e 67 6f 46 69 72 65 77 61 6c 6c } //1 com.goFirewall
		$a_01_3 = {72 65 5f 75 72 6c 3f 72 65 63 6f 72 64 3d } //1 re_url?record=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}