
rule Trojan_BAT_SnakeKeylogger_SPQE_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.SPQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 02 07 09 07 8e 69 5d 91 08 09 08 28 ?? ?? ?? 06 5d 28 ?? ?? ?? 06 61 28 ?? ?? ?? 06 07 09 17 58 } //3
	condition:
		((#a_03_0  & 1)*3) >=3
 
}