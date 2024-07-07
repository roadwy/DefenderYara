
rule Trojan_AndroidOS_SAgnt_T_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgnt.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2e 77 69 6c 6c 75 73 6e 69 6e 2e 70 72 6f 70 75 67 6e 65 72 } //1 com.willusnin.propugner
		$a_01_1 = {53 70 65 77 73 59 65 6c 70 } //1 SpewsYelp
		$a_01_2 = {42 69 6e 65 73 52 6f 74 6c } //1 BinesRotl
		$a_01_3 = {73 74 61 72 74 54 72 61 63 6b 69 6e 67 } //1 startTracking
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}