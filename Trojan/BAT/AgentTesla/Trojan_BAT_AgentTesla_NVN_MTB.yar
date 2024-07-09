
rule Trojan_BAT_AgentTesla_NVN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 09 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 28 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 00 17 13 04 00 28 ?? ?? ?? 06 d2 06 28 ?? ?? ?? 06 00 00 00 09 17 58 0d 09 17 fe 04 13 05 11 05 2d c0 } //3
		$a_81_1 = {4f 49 57 44 48 44 4a 57 44 43 48 58 } //3 OIWDHDJWDCHX
		$a_81_2 = {49 4f 55 48 46 53 48 46 49 48 59 55 47 42 43 53 } //3 IOUHFSHFIHYUGBCS
		$a_81_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*1) >=10
 
}