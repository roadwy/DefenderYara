
rule Trojan_BAT_DCRat_NDT_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 d5 15 65 bb 65 20 ?? ?? ?? 35 61 7e a0 09 00 04 7b ?? ?? ?? 04 61 28 f9 0d 00 06 73 ?? ?? ?? 06 28 55 01 00 06 20 ?? ?? ?? 00 7e a0 09 00 04 7b ?? ?? ?? 04 39 69 ff ff ff 26 20 ?? ?? ?? 00 38 5e ff ff ff 14 38 ?? ?? ?? 00 38 4a 00 00 00 00 73 ?? ?? ?? 06 26 20 01 00 00 00 7e ?? ?? ?? 04 7b b1 09 00 04 3a ?? ?? ?? ff 26 20 00 00 00 00 38 ?? ?? ?? ff 28 0f 0f 00 06 } //5
		$a_01_1 = {70 39 31 6e 61 41 50 4a 33 66 74 49 64 67 57 67 48 6e 2e 65 49 63 56 31 4a 31 30 4e 4d 58 48 74 74 6d 51 6b 43 } //1 p91naAPJ3ftIdgWgHn.eIcV1J10NMXHttmQkC
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}