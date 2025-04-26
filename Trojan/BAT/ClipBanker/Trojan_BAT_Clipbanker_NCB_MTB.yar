
rule Trojan_BAT_Clipbanker_NCB_MTB{
	meta:
		description = "Trojan:BAT/Clipbanker.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 72 bd 07 00 70 28 ?? ?? 00 0a 6f ?? ?? 00 06 6f ?? ?? 00 0a 25 07 6f ?? ?? 00 06 } //5
		$a_01_1 = {52 00 6f 00 6f 00 62 00 65 00 74 00 43 00 72 00 61 00 73 00 68 00 } //1 RoobetCrash
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_Clipbanker_NCB_MTB_2{
	meta:
		description = "Trojan:BAT/Clipbanker.NCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 13 00 fe ?? ?? 00 5c fe ?? ?? 00 58 fe ?? ?? 00 fe ?? ?? 00 fe ?? ?? 00 58 fe ?? ?? 00 5a fe ?? ?? 00 58 fe ?? ?? 00 fe ?? ?? 00 16 40 ?? ?? ?? 00 fe ?? ?? 00 17 59 fe ?? ?? 00 } //5
		$a_01_1 = {73 73 73 63 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 sssc.g.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}