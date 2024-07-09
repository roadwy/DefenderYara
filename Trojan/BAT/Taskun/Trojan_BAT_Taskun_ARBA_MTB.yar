
rule Trojan_BAT_Taskun_ARBA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ARBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f ?? ?? ?? 0a 13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 61 11 0e 59 20 00 01 00 00 58 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 11 09 17 59 13 09 11 09 16 2f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}