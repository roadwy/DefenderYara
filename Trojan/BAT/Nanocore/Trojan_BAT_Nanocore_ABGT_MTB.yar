
rule Trojan_BAT_Nanocore_ABGT_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ABGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {08 11 08 07 11 08 9a 1f 10 28 ?? ?? ?? 0a 9c 11 08 17 58 13 08 11 08 07 8e 69 fe 04 13 09 11 09 2d de } //5
		$a_01_1 = {48 00 6f 00 71 00 75 00 65 00 4c 00 74 00 64 00 2e 00 52 00 65 00 73 00 4f 00 } //1 HoqueLtd.ResO
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}