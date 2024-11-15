
rule Trojan_AndroidOS_Adbminer_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Adbminer.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 72 6f 69 64 62 6f 74 } //1 droidbot
		$a_01_1 = {63 6f 6d 2e 75 66 6f 2e 6d 69 6e 65 72 } //1 com.ufo.miner
		$a_01_2 = {61 64 62 20 2d 73 20 25 73 3a 35 35 35 35 20 73 68 65 6c 6c } //1 adb -s %s:5555 shell
		$a_01_3 = {2f 6c 6f 63 6b 30 2e 74 78 74 } //1 /lock0.txt
		$a_03_4 = {74 6d 70 2f [0-06] 2e 61 70 6b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}