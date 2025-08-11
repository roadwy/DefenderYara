
rule Trojan_BAT_Diztakun_AXC_MTB{
	meta:
		description = "Trojan:BAT/Diztakun.AXC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 72 11 00 00 70 6f 18 00 00 0a 00 06 28 19 00 00 0a 26 7e 1a 00 00 0a 72 80 01 00 70 6f 1b 00 00 0a 0b 07 72 f4 01 00 70 17 8c 22 00 00 01 17 6f 1c 00 00 0a 00 7e 1d 00 00 0a 72 12 02 00 70 6f 1b 00 00 0a 0c 08 72 7e 02 00 70 72 8a 02 00 70 17 6f 1c 00 00 0a } //2
		$a_00_1 = {50 72 6f 63 65 73 73 53 74 61 72 74 49 6e 66 6f } //1 ProcessStartInfo
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}