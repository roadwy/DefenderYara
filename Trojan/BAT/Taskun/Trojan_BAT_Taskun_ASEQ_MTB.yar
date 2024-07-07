
rule Trojan_BAT_Taskun_ASEQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ASEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff ff 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c } //1
		$a_01_1 = {48 69 65 72 61 72 63 68 79 2e 53 61 6d 70 6c 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 Hierarchy.Sample.Properties.Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}