
rule Trojan_Win32_Wabot_SCP_MTB{
	meta:
		description = "Trojan:Win32/Wabot.SCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 72 73 72 63 00 00 00 58 15 00 00 00 90 01 00 00 16 00 00 00 a0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 50 00 00 00 00 00 00 00 00 00 e0 78 00 00 b0 01 00 00 28 03 00 00 b6 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e0 2e 64 61 74 61 } //3
		$a_01_1 = {67 56 61 49 6c b2 bb 4e 1a 93 7a 65 bc 9c f4 f5 58 93 78 f5 ce 83 89 7d 32 62 d3 c3 ec 2c b1 b9 69 d2 4c 73 79 bc bb 61 2b 8b eb 1e 0c c9 ae 29 99 c1 3c 76 0e 8c 79 6f 52 62 e1 0b } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=1
 
}