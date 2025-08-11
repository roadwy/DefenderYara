
rule Trojan_BAT_Taskun_PGTK_MTB{
	meta:
		description = "Trojan:BAT/Taskun.PGTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 20 e8 03 00 00 5d 2d 24 28 ?? 00 00 0a 08 28 ?? 00 00 0a 13 0b 12 0b 28 ?? 00 00 0a 69 13 0a 09 6c 17 11 0a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}