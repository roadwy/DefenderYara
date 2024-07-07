
rule Trojan_AndroidOS_BankerAgent_H{
	meta:
		description = "Trojan:AndroidOS/BankerAgent.H,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 61 6e 6b 31 32 2e 70 68 70 3f 6d 3d 41 70 69 26 61 3d 53 6d 73 26 69 6d 73 69 3d } //2 bank12.php?m=Api&a=Sms&imsi=
		$a_01_1 = {61 62 63 2f 45 6e 41 63 74 69 76 69 74 79 } //2 abc/EnActivity
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}