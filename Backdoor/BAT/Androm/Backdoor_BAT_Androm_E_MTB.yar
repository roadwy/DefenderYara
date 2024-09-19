
rule Backdoor_BAT_Androm_E_MTB{
	meta:
		description = "Backdoor:BAT/Androm.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 09 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 10 00 dd } //3
		$a_03_1 = {11 04 72 01 00 00 70 20 00 01 00 00 14 14 14 6f ?? 00 00 0a 26 dd 06 00 00 00 26 dd 00 00 00 00 09 17 58 0d 09 08 8e 69 32 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}