
rule Trojan_BAT_LummaStealer_GSC_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 11 65 05 00 01 01 12 61 06 00 01 12 69 12 59 } //1 ᅡեĀሁ١Ā椒夒
	condition:
		((#a_01_0  & 1)*1) >=1
 
}