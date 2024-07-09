
rule Trojan_BAT_Taskun_AMAA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 07 8e 69 5d 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 09 16 2f c0 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}