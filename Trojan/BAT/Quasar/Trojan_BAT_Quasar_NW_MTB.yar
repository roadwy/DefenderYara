
rule Trojan_BAT_Quasar_NW_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 01 00 28 ?? ?? ?? 0a 2a 20 ?? ?? ?? 00 fe ?? ?? 00 00 fe ?? ?? 00 20 ?? ?? ?? 00 fe 01 39 ?? ?? ?? 00 00 20 ?? ?? ?? 00 fe ?? ?? 00 00 fe ?? ?? 00 20 ?? ?? ?? 00 fe 01 39 ?? ?? ?? 00 38 ?? ?? ?? 00 38 ?? ?? ?? ff } //5
		$a_01_1 = {67 42 59 45 42 59 45 66 75 6c 6c } //1 gBYEBYEfull
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}