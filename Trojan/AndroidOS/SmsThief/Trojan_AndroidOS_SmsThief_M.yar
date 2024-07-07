
rule Trojan_AndroidOS_SmsThief_M{
	meta:
		description = "Trojan:AndroidOS/SmsThief.M,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_00_0 = {53 4e 53 44 42 42 53 4a 4e 2f 49 53 53 41 53 44 53 } //2 SNSDBBSJN/ISSASDS
		$a_00_1 = {2f 63 6f 76 65 72 2e 68 74 6d 6c 3f 64 49 44 3d } //2 /cover.html?dID=
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2) >=4
 
}