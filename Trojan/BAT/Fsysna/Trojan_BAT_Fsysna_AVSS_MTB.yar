
rule Trojan_BAT_Fsysna_AVSS_MTB{
	meta:
		description = "Trojan:BAT/Fsysna.AVSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 08 6f ?? ?? ?? 0a 9c 00 09 17 d6 0d 09 6a 06 6f ?? ?? ?? 0a fe 04 13 08 11 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}