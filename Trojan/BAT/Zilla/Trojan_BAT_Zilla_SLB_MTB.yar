
rule Trojan_BAT_Zilla_SLB_MTB{
	meta:
		description = "Trojan:BAT/Zilla.SLB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 16 fe 01 39 03 00 00 00 00 17 0a 00 06 17 fe 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}