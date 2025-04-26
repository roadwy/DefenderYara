
rule Trojan_BAT_XWorm_PDM_MTB{
	meta:
		description = "Trojan:BAT/XWorm.PDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 03 04 05 73 99 01 00 0a 0b 07 1f 18 6f ?? ?? ?? 0a 0c 07 1e 6f ?? ?? ?? 0a 0d 00 73 9b 01 00 0a 13 04 11 04 08 6f ?? ?? ?? 0a 00 11 04 09 6f ?? ?? ?? 0a 00 11 04 17 6f ?? ?? ?? 0a 00 11 04 18 6f ?? ?? ?? 0a 00 11 04 6f ?? ?? ?? 0a 13 05 11 05 02 16 02 8e 69 6f ?? ?? ?? 0a 13 06 11 06 0a de 20 } //3
		$a_00_1 = {72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f 00 62 00 69 00 64 00 6f 00 73 00 6c 00 78 00 75 00 66 00 69 00 74 00 } //2 resources/bidoslxufit
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*2) >=5
 
}