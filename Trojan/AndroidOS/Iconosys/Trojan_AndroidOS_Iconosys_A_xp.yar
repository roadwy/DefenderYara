
rule Trojan_AndroidOS_Iconosys_A_xp{
	meta:
		description = "Trojan:AndroidOS/Iconosys.A!xp,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {62 6c 61 63 6b 66 6c 79 64 61 79 2e 63 6f 6d } //01 00  blackflyday.com
		$a_00_1 = {2f 46 75 6e 6e 79 4a 61 69 6c 2f } //01 00  /FunnyJail/
		$a_00_2 = {74 72 69 63 6b 65 72 64 61 74 61 2e 70 68 70 } //01 00  trickerdata.php
		$a_00_3 = {73 6d 73 72 65 70 6c 69 65 72 2e 6e 65 74 2f 73 6d 73 72 65 70 6c 79 } //01 00  smsreplier.net/smsreply
		$a_00_4 = {69 63 6f 6e 6f 73 79 73 65 6d 61 69 6c 40 72 6f 63 6b 65 74 6d 61 69 6c 2e 63 6f 6d } //01 00  iconosysemail@rocketmail.com
		$a_00_5 = {3a 2f 2f 64 65 74 61 69 6c 73 3f 69 64 3d 63 6f 6d 2e 73 61 6e 74 61 2e 69 63 6f 6e 6f 73 79 73 } //01 00  ://details?id=com.santa.iconosys
		$a_00_6 = {73 74 61 72 74 43 61 6d 65 72 61 41 63 74 69 76 69 74 79 } //00 00  startCameraActivity
	condition:
		any of ($a_*)
 
}