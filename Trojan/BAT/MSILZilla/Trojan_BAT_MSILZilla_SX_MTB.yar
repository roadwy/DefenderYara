
rule Trojan_BAT_MSILZilla_SX_MTB{
	meta:
		description = "Trojan:BAT/MSILZilla.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 72 01 00 00 70 12 00 73 06 00 00 0a 80 08 00 00 04 06 2d 07 16 28 07 00 00 0a 2a 28 06 00 00 06 28 08 00 00 0a 0b 12 01 fe 16 0a 00 00 01 6f 09 00 00 0a 16 1e 6f 0a 00 00 0a 6f 0b 00 00 0a 80 06 00 00 04 28 07 00 00 06 20 e8 03 00 00 28 0c 00 00 0a } //20
		$a_80_1 = {5a 65 72 6f 52 41 54 5f 43 6c 69 65 6e 74 5f 4d 75 74 65 78 } //ZeroRAT_Client_Mutex  10
	condition:
		((#a_01_0  & 1)*20+(#a_80_1  & 1)*10) >=30
 
}