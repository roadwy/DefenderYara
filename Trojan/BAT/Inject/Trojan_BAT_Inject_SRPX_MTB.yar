
rule Trojan_BAT_Inject_SRPX_MTB{
	meta:
		description = "Trojan:BAT/Inject.SRPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 07 08 93 0d 09 20 ff 00 00 00 5f 06 25 17 58 0a 61 1e 62 09 1e 63 06 25 17 58 0a 61 d2 60 d1 9d 18 2b b4 08 17 58 0c 19 2b ad 2b ca 07 73 3c 00 00 0a 28 ?? ?? ?? 0a } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}