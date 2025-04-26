
rule Trojan_BAT_Hawkeye_AIOW_MTB{
	meta:
		description = "Trojan:BAT/Hawkeye.AIOW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 d6 13 04 11 04 16 28 ?? ?? ?? 06 7e 01 00 00 04 d8 fe 04 13 06 11 06 2c 0b 16 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}