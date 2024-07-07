
rule Trojan_BAT_Taskun_AMMG_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 11 90 02 0a 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}