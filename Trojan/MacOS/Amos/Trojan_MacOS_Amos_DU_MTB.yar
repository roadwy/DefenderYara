
rule Trojan_MacOS_Amos_DU_MTB{
	meta:
		description = "Trojan:MacOS/Amos.DU!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 8a 3c 11 40 30 c7 40 80 f7 07 40 88 ?? ?? ?? ?? ?? ?? 69 c0 ?? ?? 00 00 48 89 c7 48 0f af fe 48 c1 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}