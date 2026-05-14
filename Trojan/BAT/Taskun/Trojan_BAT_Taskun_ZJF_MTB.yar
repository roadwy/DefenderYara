
rule Trojan_BAT_Taskun_ZJF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZJF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 07 08 91 28 ?? 00 00 06 08 1f 16 5d 91 61 07 08 17 58 09 5d 91 59 20 00 01 00 00 58 d2 9c 08 17 58 0c 08 09 fe 04 13 06 11 06 2d d2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}