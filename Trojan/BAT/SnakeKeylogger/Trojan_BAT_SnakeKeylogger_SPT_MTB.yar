
rule Trojan_BAT_SnakeKeylogger_SPT_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 00 65 00 63 00 75 00 72 00 65 00 4d 00 6f 00 64 00 65 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2 SecureMode.Properties.Resources
		$a_81_1 = {24 34 42 31 45 38 41 45 36 2d 30 39 43 38 2d 34 34 38 30 2d 38 33 39 39 2d 33 44 31 37 34 30 45 41 45 32 37 37 } //1 $4B1E8AE6-09C8-4480-8399-3D1740EAE277
		$a_81_2 = {31 2e 36 2e 31 39 30 38 2e 30 } //1 1.6.1908.0
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}