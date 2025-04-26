
rule Trojan_BAT_Zusy_NZS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 1e 17 d6 13 1e 11 09 6f ?? ?? ?? 0a 13 0a 11 1e 1b 3e ?? ?? ?? 00 11 0b 2c 3e 11 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2c 1b 16 13 0b 11 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 17 38 ?? ?? ?? 00 } //5
		$a_01_1 = {4d 38 59 20 44 61 74 61 20 4d 61 69 6c 20 32 20 43 53 56 } //1 M8Y Data Mail 2 CSV
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}