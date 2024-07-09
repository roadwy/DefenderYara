
rule TrojanDropper_BAT_Gendwndrop_D_bit{
	meta:
		description = "TrojanDropper:BAT/Gendwndrop.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 19 00 00 0a 0c 08 06 07 03 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f ?? 00 00 0a } //1
		$a_01_1 = {50 00 72 00 6f 00 74 00 65 00 63 00 74 00 6f 00 72 00 } //1 Protector
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}