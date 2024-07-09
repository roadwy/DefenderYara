
rule Trojan_BAT_Taskun_KAN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 5d d4 91 08 11 ?? d4 91 61 07 11 ?? 07 8e 69 6a 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}