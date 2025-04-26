
rule Trojan_AndroidOS_Rewardsteal_AS{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AS,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 65 72 6d 69 73 69 69 6f 6e 65 52 65 71 75 65 73 74 } //2 PermisiioneRequest
		$a_01_1 = {63 72 65 61 74 65 20 74 61 62 6c 65 20 75 73 65 72 73 20 28 69 64 20 69 6e 74 65 67 65 72 20 70 72 69 6d 61 72 79 20 6b 65 79 2c 73 65 72 76 65 72 69 64 20 74 65 78 74 29 } //2 create table users (id integer primary key,serverid text)
		$a_01_2 = {41 63 74 69 76 69 74 79 47 6b 65 79 62 6f 61 72 64 42 69 6e 64 69 6e 67 } //2 ActivityGkeyboardBinding
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}