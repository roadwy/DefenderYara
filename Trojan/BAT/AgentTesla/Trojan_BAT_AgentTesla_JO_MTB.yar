
rule Trojan_BAT_AgentTesla_JO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 75 30 55 47 4d 52 63 52 46 70 47 34 35 4d 4d 48 79 2e 34 30 67 30 38 44 74 73 69 34 56 70 63 4b 68 69 58 63 } //2 su0UGMRcRFpG45MMHy.40g08Dtsi4VpcKhiXc
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //2 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_2 = {54 6a 6d 78 6d 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //2 Tjmxm.g.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}