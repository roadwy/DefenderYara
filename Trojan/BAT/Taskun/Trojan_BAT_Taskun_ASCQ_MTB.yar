
rule Trojan_BAT_Taskun_ASCQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ASCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {58 0d 2b 3e 00 07 09 07 8e 69 5d 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 07 09 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 13 07 07 09 07 8e 69 5d 11 07 20 00 01 00 00 5d d2 9c 09 15 58 0d 00 09 16 fe 04 16 fe 01 13 08 11 08 2d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}