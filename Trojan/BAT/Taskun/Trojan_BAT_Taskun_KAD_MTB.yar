
rule Trojan_BAT_Taskun_KAD_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 07 11 12 07 8e 69 5d 07 11 12 07 8e 69 5d 91 08 11 12 1f 16 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 07 11 12 17 58 07 8e 69 5d 91 28 90 01 01 00 00 0a 59 20 90 01 02 00 00 58 20 90 01 02 00 00 5d 28 90 01 01 00 00 0a 9c 00 11 12 15 58 13 12 11 12 16 fe 04 16 fe 01 13 13 11 13 2d a8 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}