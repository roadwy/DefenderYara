
rule Trojan_BAT_PureLog_KAG_MTB{
	meta:
		description = "Trojan:BAT/PureLog.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 0d 58 11 06 11 03 95 58 20 ff 00 00 00 5f 13 04 ?? ?? ?? ?? ?? 11 0e 11 10 61 13 13 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}