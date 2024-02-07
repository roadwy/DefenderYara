
rule TrojanDropper_AndroidOS_BankerAgent_X{
	meta:
		description = "TrojanDropper:AndroidOS/BankerAgent.X,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {64 6e 5f 73 73 6c } //02 00  dn_ssl
		$a_00_1 = {64 65 63 72 79 70 74 } //01 00  decrypt
		$a_00_2 = {73 63 72 74 2e 61 70 6b } //00 00  scrt.apk
		$a_00_3 = {5d 04 00 00 } //61 be 
	condition:
		any of ($a_*)
 
}