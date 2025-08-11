
rule Trojan_BAT_Taskun_MCF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MCF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 2c 91 7e ?? 00 00 04 20 ?? 01 00 00 91 61 1f 1c 5f 9c 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}