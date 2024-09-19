
rule Trojan_AndroidOS_Fakecalls_U{
	meta:
		description = "Trojan:AndroidOS/Fakecalls.U,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {70 79 6d 46 69 6c 78 45 } //1 pymFilxE
		$a_01_1 = {45 41 79 67 61 49 7a 70 6b 6d } //1 EAygaIzpkm
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}