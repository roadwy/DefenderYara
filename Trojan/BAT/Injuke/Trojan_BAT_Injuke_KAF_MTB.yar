
rule Trojan_BAT_Injuke_KAF_MTB{
	meta:
		description = "Trojan:BAT/Injuke.KAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 91 02 07 02 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 28 ?? 00 00 06 8e 69 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}