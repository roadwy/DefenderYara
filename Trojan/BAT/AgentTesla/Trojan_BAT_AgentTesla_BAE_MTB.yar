
rule Trojan_BAT_AgentTesla_BAE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 11 20 e8 03 00 00 13 12 20 e8 03 00 00 8d 90 01 03 01 13 14 2b 19 11 13 11 12 2f 13 2b 26 7e 90 01 03 04 11 14 16 11 13 6f 90 01 03 0a 2b e7 11 11 11 14 16 11 12 6f 90 01 03 0a 13 13 11 13 16 31 d4 2b da 90 00 } //2
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //2 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}