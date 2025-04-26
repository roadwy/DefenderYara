
rule Trojan_BAT_Taskun_SVJA_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SVJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {95 58 20 ff 00 00 00 5f 13 0c 11 0c 1f 7b 61 20 ff 00 00 00 5f 13 0d 11 0d 20 ?? 01 00 00 58 20 00 01 00 00 5e 13 0d 11 0d 16 fe 01 13 0e 11 0e 2c 03 17 13 0d 09 11 0b 07 11 0b 91 11 04 11 0c 95 61 d2 9c } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}