
rule Trojan_BAT_AgentTesla_NPV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_80_0 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f } //transfer.sh/get/  01 00 
		$a_01_1 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 } //01 00  aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resource
		$a_80_2 = {4b 4a 4c 44 4b 53 44 48 53 44 4b 55 49 2e 56 45 43 54 4f 52 } //KJLDKSDHSDKUI.VECTOR  01 00 
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_80_4 = {2e 33 30 33 31 39 5c 61 73 70 6e 65 74 5f 63 6f } //.30319\aspnet_co  01 00 
		$a_01_5 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_80_6 = {54 52 41 53 48 } //TRASH  00 00 
	condition:
		any of ($a_*)
 
}