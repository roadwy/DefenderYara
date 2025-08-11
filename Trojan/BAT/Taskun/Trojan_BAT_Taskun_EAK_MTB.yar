
rule Trojan_BAT_Taskun_EAK_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 06 7b 06 01 00 04 11 24 11 09 91 ?? ?? ?? ?? ?? 00 00 11 09 17 58 13 09 11 09 11 16 fe 04 13 25 11 25 2d db } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}