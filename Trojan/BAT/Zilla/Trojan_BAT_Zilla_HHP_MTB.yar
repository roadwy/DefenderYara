
rule Trojan_BAT_Zilla_HHP_MTB{
	meta:
		description = "Trojan:BAT/Zilla.HHP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 11 05 07 11 05 91 06 11 05 06 8e 69 5d 91 11 05 09 58 06 8e 69 58 1d 5f 1f ?? 5f 62 d2 20 ?? ?? ?? ?? 5d 61 d2 9c 11 05 17 58 13 05 11 05 11 04 31 cd } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}