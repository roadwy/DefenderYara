
rule Trojan_BAT_Redcap_GMZ_MTB{
	meta:
		description = "Trojan:BAT/Redcap.GMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 05 11 05 2c 2b 00 11 04 72 03 37 00 70 06 72 6b 36 00 70 6f ?? ?? ?? 0a 06 72 77 36 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 00 72 35 37 00 70 11 04 28 ?? ?? ?? 0a 26 } //10
		$a_01_1 = {67 65 74 5f 62 61 73 65 6c 69 6e 65 5f 63 6c 65 61 72 5f 62 6c 61 63 6b 5f 31 38 64 70 31 } //1 get_baseline_clear_black_18dp1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}