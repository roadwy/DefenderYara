
rule Trojan_BAT_Tedy_RW_MTB{
	meta:
		description = "Trojan:BAT/Tedy.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 08 0e 04 0e 04 8e 69 12 04 11 05 11 05 8e 69 09 09 8e 69 12 06 16 28 ?? ?? ?? 06 13 07 11 07 7e ?? ?? ?? ?? fe 01 13 09 11 09 2c 0b 72 } //5
		$a_01_1 = {50 69 6c 6c 61 67 65 72 2e 64 6c 6c } //1 Pillager.dll
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}