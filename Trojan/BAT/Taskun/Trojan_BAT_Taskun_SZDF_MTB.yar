
rule Trojan_BAT_Taskun_SZDF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SZDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 2c 53 00 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0b 02 07 1f 10 63 20 ff 00 00 00 5f d2 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}