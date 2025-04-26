
rule Trojan_BAT_SnakeKeylogger_SPRY_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPRY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 0d 02 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 16 28 ?? ?? ?? 06 0c de 20 07 14 fe 01 0d 09 2d 07 07 6f ?? ?? ?? 0a 00 dc } //3
		$a_01_1 = {57 69 6e 64 6f 77 73 5f 4c 6f 63 61 6c 5f 48 6f 73 74 5f 50 72 6f 7a 65 73 73 } //1 Windows_Local_Host_Prozess
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}