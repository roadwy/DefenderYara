
rule Trojan_BAT_SnakeKeylogger_SL_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 07 8e 69 5d 13 11 07 11 11 11 0f 11 10 91 9c 03 11 0f 11 10 91 6f 4d 00 00 0a 08 17 58 07 8e 69 5d 0c 11 10 17 58 13 10 11 10 11 0d 32 d1 } //2
		$a_01_1 = {50 61 72 6b 4d 61 73 74 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 ParkMaster.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}