
rule Trojan_BAT_Lazy_AMBB_MTB{
	meta:
		description = "Trojan:BAT/Lazy.AMBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 00 00 7e ?? 00 00 04 fe 0c 04 00 6f ?? 00 00 0a fe 0e 05 00 fe 0d 05 00 28 ?? ?? 00 0a 28 ?? 00 00 0a fe 0e 00 00 20 ?? ?? 00 00 fe 0e 06 00 } //2
		$a_03_1 = {fe 0c 01 00 fe 0c 02 00 6f ?? 00 00 0a fe 0e 03 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}