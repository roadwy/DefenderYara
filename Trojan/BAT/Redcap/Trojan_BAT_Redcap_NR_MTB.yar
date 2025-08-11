
rule Trojan_BAT_Redcap_NR_MTB{
	meta:
		description = "Trojan:BAT/Redcap.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 09 00 00 01 0a 06 20 00 00 00 00 fe 09 00 00 a2 06 28 ?? 07 00 06 74 10 00 00 01 } //2
		$a_01_1 = {48 6f 66 66 43 6f 6e 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 HoffCon.Resources.resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}