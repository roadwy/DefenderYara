
rule Trojan_BAT_CryptoObf_CI_MTB{
	meta:
		description = "Trojan:BAT/CryptoObf.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {70 0a 06 28 ?? 00 00 0a 25 26 0b 28 4b 00 00 0a [0-02] 07 16 07 8e 69 6f 4c 00 00 0a 25 26 0a 28 ?? 00 00 0a 25 26 06 6f ?? 00 00 0a [0-03] 0c 1f 61 6a 08 28 27 00 00 06 25 26 80 08 00 00 04 } //2
		$a_01_1 = {4d 61 6c 69 63 69 6f 75 73 50 72 6f 67 72 61 6d } //1 MaliciousProgram
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}