
rule Trojan_BAT_Taskun_PMAH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.PMAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 05 95 11 04 11 06 95 58 20 ff 00 00 00 5f 13 0b 11 0b 1f 7b 61 20 ff 00 00 00 5f 20 ?? ?? ?? ?? 58 20 00 01 00 00 5e 26 09 11 0a 07 11 0a 91 11 04 11 0b 95 61 d2 9c 11 0a 17 58 13 0a 11 0a 07 8e 69 32 85 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}