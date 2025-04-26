
rule Trojan_BAT_Quasar_NQP_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0d 00 00 0a 02 6f ?? ?? ?? 0a 0a 03 18 18 73 ?? ?? ?? 0a 0b 06 07 6f 10 00 00 0a } //5
		$a_01_1 = {53 65 72 6f 58 65 6e 5f 44 72 6f 70 70 65 72 } //1 SeroXen_Dropper
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}