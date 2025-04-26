
rule Trojan_BAT_AgentTesla_SPPE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 18 6f ?? ?? ?? 0a 13 07 08 11 06 18 5b 11 07 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 06 18 58 13 06 11 06 07 6f ?? ?? ?? 0a fe 04 13 08 11 08 2d cd } //4
		$a_01_1 = {43 69 6e 65 6d 61 4d 61 6e 61 67 65 6d 65 6e 74 2e 46 72 53 75 61 74 43 68 69 65 75 2e 72 65 73 6f 75 72 63 65 73 } //1 CinemaManagement.FrSuatChieu.resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}