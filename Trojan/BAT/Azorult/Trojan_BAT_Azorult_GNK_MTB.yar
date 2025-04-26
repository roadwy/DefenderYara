
rule Trojan_BAT_Azorult_GNK_MTB{
	meta:
		description = "Trojan:BAT/Azorult.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 20 11 1f 11 21 6f ?? ?? ?? 0a 11 1d 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 26 11 21 17 58 13 21 11 21 11 1f 6f ?? ?? ?? 0a fe 04 13 22 11 22 2d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}