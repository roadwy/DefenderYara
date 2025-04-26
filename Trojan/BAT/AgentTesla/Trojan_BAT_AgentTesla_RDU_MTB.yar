
rule Trojan_BAT_AgentTesla_RDU_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 62 33 39 63 35 31 38 2d 63 63 64 66 2d 34 61 64 33 2d 39 30 64 32 2d 30 66 61 65 65 64 37 38 64 37 30 34 } //1 eb39c518-ccdf-4ad3-90d2-0faeed78d704
		$a_01_1 = {4c 4b 4d 50 4f 37 } //1 LKMPO7
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 } //1 aR3nbf8dQp2feLmk31
		$a_01_3 = {6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 } //1 lSfgApatkdxsVcGcrktoFd
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}