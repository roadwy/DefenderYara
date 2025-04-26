
rule Trojan_BAT_Lazy_GPBX_MTB{
	meta:
		description = "Trojan:BAT/Lazy.GPBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 01 39 24 00 00 00 00 00 23 00 [0-10] c1 23 00 00 [0-12] 28 ?? 00 00 0a fe } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}