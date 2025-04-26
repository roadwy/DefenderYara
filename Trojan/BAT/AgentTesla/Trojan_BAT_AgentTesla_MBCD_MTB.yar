
rule Trojan_BAT_AgentTesla_MBCD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 63 64 32 65 61 33 33 38 2d 35 39 36 30 2d 34 35 37 37 2d 38 37 34 65 2d 64 32 65 61 62 64 39 63 62 30 65 34 } //10 $cd2ea338-5960-4577-874e-d2eabd9cb0e4
		$a_01_1 = {46 00 79 00 6f 00 64 00 6f 00 72 00 44 00 6f 00 73 00 74 00 6f 00 79 00 65 00 76 00 73 00 6b 00 79 00 } //1 FyodorDostoyevsky
		$a_01_2 = {50 00 6c 00 61 00 79 00 65 00 72 00 44 00 61 00 74 00 61 00 2e 00 78 00 6d 00 6c 00 } //1 PlayerData.xml
		$a_01_3 = {45 6e 67 69 6e 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Engine.Properties.Resources.resources
		$a_01_4 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resource
		$a_01_5 = {57 9d a2 29 09 0b 00 00 00 00 00 00 00 00 00 00 02 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}