
rule Trojan_BAT_Taskun_AMAO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 13 [0-14] 61 [0-0f] 17 58 08 5d 13 [0-20] 20 00 01 00 00 58 [0-08] 20 ff 00 00 00 5f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}