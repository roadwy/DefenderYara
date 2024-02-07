
rule Trojan_BAT_AgentTesla_NQQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 0b 11 0c 58 09 11 0c 58 47 52 00 11 0c 17 58 13 0c 11 0c 07 8e 69 fe 04 13 0d 11 0d 2d e0 } //01 00 
		$a_01_1 = {1f 53 00 79 00 73 00 74 00 65 00 6d 00 20 00 54 00 72 00 61 00 79 00 20 00 41 00 70 00 70 00 00 09 45 00 78 00 69 00 74 } //01 00 
		$a_81_2 = {42 61 72 65 41 6d 73 4d 65 74 61 6c 69 53 63 42 61 72 65 61 6e 42 75 4d 65 74 61 6c 66 66 65 72 } //01 00  BareAmsMetaliScBareanBuMetalffer
		$a_81_3 = {42 61 72 65 61 6d 4d 65 74 61 6c 73 69 2e 42 61 72 65 64 6c 6c } //01 00  BareamMetalsi.Baredll
		$a_81_4 = {47 65 74 42 61 72 65 54 79 70 65 4d 65 74 61 6c } //01 00  GetBareTypeMetal
		$a_81_5 = {42 61 72 65 41 73 73 65 4d 65 74 61 6c 6d 62 6c 79 } //01 00  BareAsseMetalmbly
		$a_81_6 = {4d 65 74 61 6c 4c 6f 42 61 72 65 61 64 } //01 00  MetalLoBaread
		$a_81_7 = {4d 65 74 61 6c 45 6e 74 72 79 42 61 72 65 50 6f 69 6e 74 } //01 00  MetalEntryBarePoint
		$a_81_8 = {4d 65 74 61 6c 49 6e 42 61 72 65 76 6f 6b 65 } //01 00  MetalInBarevoke
		$a_81_9 = {50 52 49 59 41 54 4e 4f } //00 00  PRIYATNO
	condition:
		any of ($a_*)
 
}