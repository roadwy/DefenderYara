
rule Trojan_AndroidOS_Mobstart_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Mobstart.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 68 7a 64 69 2e 68 61 70 70 79 62 69 72 64 } //05 00  com.hzdi.happybird
		$a_00_1 = {63 6f 6d 2e 6d 6f 62 69 73 74 61 72 74 61 70 70 2e 63 6f 64 65 72 6f 75 74 65 2e 68 7a 70 65 72 6d 69 73 70 72 6f 2e 61 72 } //01 00  com.mobistartapp.coderoute.hzpermispro.ar
		$a_00_2 = {50 75 73 68 41 64 41 63 74 69 76 69 74 79 } //01 00  PushAdActivity
		$a_00_3 = {50 75 73 68 4e 6f 74 69 66 52 6f 75 74 65 72 41 63 74 69 76 69 74 79 } //01 00  PushNotifRouterActivity
		$a_00_4 = {72 65 6d 6f 74 65 4d 65 73 73 61 67 65 } //01 00  remoteMessage
		$a_00_5 = {50 75 62 41 63 74 69 76 69 74 79 } //00 00  PubActivity
	condition:
		any of ($a_*)
 
}