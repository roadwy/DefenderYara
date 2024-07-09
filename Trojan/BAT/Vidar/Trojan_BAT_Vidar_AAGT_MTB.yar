
rule Trojan_BAT_Vidar_AAGT_MTB{
	meta:
		description = "Trojan:BAT/Vidar.AAGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 06 08 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d 09 13 04 11 04 2a } //3
		$a_01_1 = {44 00 61 00 74 00 61 00 42 00 61 00 73 00 65 00 50 00 72 00 61 00 63 00 74 00 69 00 63 00 61 00 6c 00 4a 00 6f 00 62 00 } //1 DataBasePracticalJob
		$a_01_2 = {45 00 68 00 73 00 4d 00 43 00 70 00 4c 00 45 00 6b 00 72 00 4f 00 66 00 6b 00 44 00 72 00 70 00 55 00 68 00 69 00 77 00 66 00 78 00 76 00 } //1 EhsMCpLEkrOfkDrpUhiwfxv
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}