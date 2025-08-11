
rule Trojan_BAT_Taskun_EDL_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 08 18 5f 17 63 13 05 2b 52 00 07 02 11 04 11 05 ?? ?? ?? ?? ?? 13 06 04 03 ?? ?? ?? ?? ?? 59 13 07 11 07 19 ?? ?? ?? ?? ?? 13 08 11 08 2c 0d 00 03 11 06 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}