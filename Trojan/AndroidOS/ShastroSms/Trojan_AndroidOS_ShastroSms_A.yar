
rule Trojan_AndroidOS_ShastroSms_A{
	meta:
		description = "Trojan:AndroidOS/ShastroSms.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 63 79 61 2e 64 62 } //01 00  ycya.db
		$a_01_1 = {70 61 79 5f 61 73 74 72 6f 5f 73 68 61 70 79 } //01 00  pay_astro_shapy
		$a_01_2 = {73 65 6e 64 59 63 79 61 } //01 00  sendYcya
		$a_01_3 = {76 61 6c 24 70 61 79 6e 61 6d 65 } //01 00  val$payname
		$a_01_4 = {74 61 5f 61 73 74 72 6f } //01 00  ta_astro
		$a_01_5 = {67 6f 6e 65 49 66 46 61 69 6c } //01 00  goneIfFail
		$a_01_6 = {43 6f 75 6e 74 55 73 65 72 46 6c 61 67 2e 64 62 } //01 00  CountUserFlag.db
		$a_01_7 = {61 70 69 2e 67 6f 31 30 38 2e 63 6e 2f 63 6c 69 65 6e 74 2f 74 72 61 63 65 2f 70 61 79 2f 43 6c 69 65 6e 74 3a } //01 00  api.go108.cn/client/trace/pay/Client:
		$a_01_8 = {61 73 74 72 6f 2f 63 69 6e 2e 6a 73 70 3f 63 3d 61 71 6c 6c } //00 00  astro/cin.jsp?c=aqll
	condition:
		any of ($a_*)
 
}