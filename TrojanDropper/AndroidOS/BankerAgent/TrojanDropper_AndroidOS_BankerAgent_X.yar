
rule TrojanDropper_AndroidOS_BankerAgent_X{
	meta:
		description = "TrojanDropper:AndroidOS/BankerAgent.X,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_00_0 = {64 6e 5f 73 73 6c } //2 dn_ssl
		$a_00_1 = {64 65 63 72 79 70 74 } //2 decrypt
		$a_00_2 = {73 63 72 74 2e 61 70 6b } //1 scrt.apk
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1) >=5
 
}