
rule Trojan_BAT_GameCheat_J_ibt{
	meta:
		description = "Trojan:BAT/GameCheat.J!ibt,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 20 00 61 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 } //1 Disable antivirus
		$a_01_1 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 42 00 61 00 74 00 74 00 6c 00 45 00 79 00 65 00 } //1 \Device\BattlEye
		$a_01_2 = {2e 00 65 00 75 00 72 00 6f 00 64 00 69 00 72 00 2e 00 72 00 75 00 } //1 .eurodir.ru
		$a_01_3 = {76 00 6b 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 72 00 6d 00 61 00 32 00 6f 00 61 00 5f 00 68 00 61 00 63 00 6b 00 } //1 vk.com/arma2oa_hack
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}