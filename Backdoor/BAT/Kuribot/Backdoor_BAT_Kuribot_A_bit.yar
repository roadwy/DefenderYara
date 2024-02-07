
rule Backdoor_BAT_Kuribot_A_bit{
	meta:
		description = "Backdoor:BAT/Kuribot.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 74 00 65 00 6c 00 65 00 67 00 72 00 61 00 2e 00 70 00 68 00 2f 00 4b 00 75 00 72 00 2d 00 } //01 00  http://telegra.ph/Kur-
		$a_01_1 = {4b 75 72 69 79 61 6d 61 2e 69 6e 73 74 61 6c 6c } //01 00  Kuriyama.install
		$a_01_2 = {4b 75 72 69 79 61 6d 61 2e 63 6f 6e 74 72 6f 6c } //01 00  Kuriyama.control
		$a_01_3 = {4b 75 72 69 79 61 6d 61 2e 64 64 6f 73 } //01 00  Kuriyama.ddos
		$a_01_4 = {4b 75 72 69 79 61 6d 61 2e 76 6d 64 65 74 65 63 74 } //00 00  Kuriyama.vmdetect
	condition:
		any of ($a_*)
 
}