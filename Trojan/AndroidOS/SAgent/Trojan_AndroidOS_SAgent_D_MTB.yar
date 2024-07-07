
rule Trojan_AndroidOS_SAgent_D_MTB{
	meta:
		description = "Trojan:AndroidOS/SAgent.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 70 70 5f 64 62 3d 61 70 6b 73 5f 64 61 74 61 } //1 app_db=apks_data
		$a_00_1 = {73 69 78 74 69 78 2e 63 68 61 69 6e 65 72 2e 72 61 64 69 6f } //1 sixtix.chainer.radio
		$a_00_2 = {07 42 1f 02 35 0f 5a 20 8d 24 07 42 1f 02 35 0f 5b 25 8e 24 07 42 1f 02 35 0f 11 02 } //2
		$a_00_3 = {54 60 92 25 16 03 00 08 72 40 98 68 20 43 0b 00 16 02 ff ff 31 04 00 02 38 04 03 00 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2) >=3
 
}