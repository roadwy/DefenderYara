
rule Trojan_BAT_Clipbanker_SPBN_MTB{
	meta:
		description = "Trojan:BAT/Clipbanker.SPBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 07 03 6f ?? ?? ?? 0a 07 04 6f ?? ?? ?? 0a 73 e3 00 00 0a 0c 07 6f ?? ?? ?? 0a 0d 08 09 17 73 e5 00 00 0a 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}