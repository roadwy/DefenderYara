
rule Trojan_BAT_Taskun_SL_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 11 12 07 8e 69 5d 07 11 12 07 8e 69 5d 91 08 11 12 1f 16 5d 6f 41 00 00 0a 61 28 42 00 00 0a 07 11 12 17 58 07 8e 69 5d 91 28 43 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 44 00 00 0a 9c 00 11 12 15 58 13 12 11 12 16 fe 04 16 fe 01 13 13 11 13 2d a8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}