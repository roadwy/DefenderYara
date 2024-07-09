
rule Trojan_BAT_QuasarRAT_R_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.R!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 00 04 08 16 07 16 1f 10 28 ?? ?? 00 06 7e ?? ?? 00 04 08 16 07 1f 0f 1f 10 28 } //2
		$a_01_1 = {47 65 74 54 65 6d 70 46 69 6c 65 4e 61 6d 65 } //1 GetTempFileName
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}