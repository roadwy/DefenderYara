
rule Trojan_BAT_Taskun_SPKM_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 09 5d 13 0d 08 11 0b 91 11 0c 61 13 0e 08 11 0d 91 13 0f 02 11 0e 11 0f 59 28 ?? ?? ?? 06 13 10 08 11 0b 11 10 28 ?? ?? ?? 0a 9c 00 11 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}