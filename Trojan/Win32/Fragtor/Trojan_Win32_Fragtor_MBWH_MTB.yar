
rule Trojan_Win32_Fragtor_MBWH_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.MBWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {20 4d 24 00 60 97 24 00 05 00 b1 00 00 00 00 00 2c b3 98 7c ff ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 a0 0f 00 00 00 00 00 00 00 00 00 00 30 97 24 00 90 97 24 00 05 00 b1 00 00 00 00 00 2c b3 98 7c ff ff ff ff 00 00 00 00 00 00 00 00 00 00 00 00 a0 0f 00 00 00 00 00 00 00 00 00 00 60 97 24 00 a0 a7 24 00 01 02 b1 00 00 00 00 00 46 61 69 6c 65 64 20 74 6f 20 6f 70 65 6e 20 63 6f 6e 66 69 67 20 66 69 6c 65 3a 20 70 61 79 6c 6f 61 64 2e 69 6e 69 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}