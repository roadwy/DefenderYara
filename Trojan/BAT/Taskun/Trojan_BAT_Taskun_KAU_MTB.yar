
rule Trojan_BAT_Taskun_KAU_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 13 [0-50] 05 95 58 20 ff 00 00 00 5f 95 61 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}