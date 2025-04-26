
rule Trojan_BAT_AveMariaRAT_R_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 0c 03 16 31 09 03 08 6f ?? 00 00 0a 32 06 } //2
		$a_03_1 = {08 03 17 59 6f ?? 00 00 0a 06 7b ?? 00 00 04 8e 69 58 0d 08 03 6f ?? 00 00 0a 09 59 13 04 06 7b ?? 00 00 04 09 28 } //4
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*4) >=6
 
}