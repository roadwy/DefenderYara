
rule Trojan_BAT_Taskun_BN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.BN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c } //3
		$a_01_1 = {2b 15 03 16 fe 02 13 05 11 05 2c 0b 00 02 03 04 28 } //1
		$a_01_2 = {0d 07 08 09 28 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}