
rule Trojan_BAT_Vidar_NVV_MTB{
	meta:
		description = "Trojan:BAT/Vidar.NVV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 60 58 0e 07 0e 04 e0 95 58 7e ?? ?? 00 04 0e 06 17 59 e0 95 58 0e 05 28 ?? ?? 00 06 58 } //5
		$a_01_1 = {6d 69 63 72 6f 70 61 74 63 68 32 64 6c 6c 5f 63 6f 6d 70 6c 65 61 74 65 } //1 micropatch2dll_compleate
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}