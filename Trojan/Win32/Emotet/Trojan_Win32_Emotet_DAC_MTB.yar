
rule Trojan_Win32_Emotet_DAC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c7 01 81 e7 90 01 04 0f b6 44 3c 1c 03 e8 81 e5 90 1b 00 0f b6 5c 2c 1c 6a 00 88 5c 3c 20 6a 00 89 44 24 18 88 44 2c 24 ff 15 90 01 04 02 5c 24 10 83 c6 01 0f b6 c3 8a 4c 04 1c 8b 44 24 18 30 4c 30 ff 3b b4 24 74 03 00 00 7c b0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}