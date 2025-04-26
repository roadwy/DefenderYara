
rule Trojan_BAT_Injuke_AMX_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 66 d2 9c [0-ff] 02 06 8f ?? 00 00 01 25 71 ?? 00 00 01 1f ?? 59 d2 81 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}