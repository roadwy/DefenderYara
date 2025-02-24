
rule Trojan_BAT_Taskun_BL_MTB{
	meta:
		description = "Trojan:BAT/Taskun.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 00 07 17 58 0b 00 07 02 6f ?? 00 00 0a 2f 0b 03 6f ?? 00 00 0a 04 fe 04 2b 01 16 0c 08 2d } //3
		$a_03_1 = {0d 07 08 09 28 ?? 00 00 06 00 } //1
		$a_01_2 = {07 17 58 0b 07 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}