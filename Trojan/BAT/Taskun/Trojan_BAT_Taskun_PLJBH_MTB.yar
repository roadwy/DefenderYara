
rule Trojan_BAT_Taskun_PLJBH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.PLJBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 25 16 02 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 02 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 02 20 ?? 00 00 00 5f d2 9c 0b 18 0d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}