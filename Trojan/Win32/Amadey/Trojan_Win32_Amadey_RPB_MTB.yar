
rule Trojan_Win32_Amadey_RPB_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 02 00 00 "
		
	strings :
		$a_01_0 = {d6 b6 42 53 92 d7 2c 00 92 d7 2c 00 92 d7 2c 00 86 bc 2f 01 9f d7 2c 00 86 bc 29 01 28 d7 2c 00 c0 a2 28 01 80 d7 2c 00 c0 a2 2f 01 84 d7 2c 00 c0 a2 29 01 cb d7 2c 00 a3 8b d1 00 90 d7 2c 00 86 bc 28 01 85 d7 2c 00 86 bc 2d 01 81 d7 2c 00 92 d7 2d 00 62 d7 2c 00 5e a2 25 01 93 d7 2c 00 5e a2 d3 00 93 d7 2c 00 5e a2 2e 01 93 d7 2c 00 52 69 63 68 92 d7 2c } //100
		$a_01_1 = {5c 5c 2e 5c 47 6c 6f 62 61 6c 5c 6f 72 65 61 6e 73 78 36 34 } //1 \\.\Global\oreansx64
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*1) >=101
 
}