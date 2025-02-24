
rule Trojan_AndroidOS_RewardSteal_Y_MTB{
	meta:
		description = "Trojan:AndroidOS/RewardSteal.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {12 00 72 20 8e cb 04 00 0a 00 71 10 b5 cb 00 00 0c 00 72 20 79 ec 05 00 0c 00 1f 00 bf 1b 22 01 84 1f 12 12 71 10 dc f6 04 00 0a 03 70 30 ba f0 21 03 6e 10 ca f0 01 00 0c 01 6e 10 ff e1 01 00 } //1
		$a_01_1 = {d8 02 01 ff 72 20 8e cb 13 00 0a 01 71 10 b5 cb 01 00 0c 01 71 10 b5 cb 00 00 0c 00 72 30 7d ec 14 00 0c 00 1f 00 b8 1b 6e 10 95 cb 00 00 0a 00 01 21 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}