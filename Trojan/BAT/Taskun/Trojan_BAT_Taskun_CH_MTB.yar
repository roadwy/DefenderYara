
rule Trojan_BAT_Taskun_CH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {04 03 61 1f 3c 59 06 61 45 ?? ?? ?? ?? ?? ?? ?? ?? 11 05 20 ?? ?? ?? ?? 94 20 ?? ?? ?? ?? 59 0d 2b a3 11 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}