
rule Trojan_BAT_DuckTail_ADI_MTB{
	meta:
		description = "Trojan:BAT/DuckTail.ADI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 2b 31 09 11 04 9a 13 05 11 05 6f ?? 01 00 0a 72 ?? d8 00 70 6f ?? 00 00 0a 2c 0a 1f fd fe 1c 78 00 00 01 58 0b 11 04 1f fd fe 1c 78 00 00 01 58 58 13 04 11 04 09 8e 69 32 c8 } //2
		$a_01_1 = {66 00 64 00 6f 00 67 00 65 00 5f 00 43 00 68 00 61 00 6e 00 67 00 65 00 41 00 63 00 63 00 56 00 49 00 50 00 2e 00 65 00 78 00 65 00 } //1 fdoge_ChangeAccVIP.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}