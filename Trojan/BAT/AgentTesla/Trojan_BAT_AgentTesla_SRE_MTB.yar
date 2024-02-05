
rule Trojan_BAT_AgentTesla_SRE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SRE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 0b 00 00 0a 00 "
		
	strings :
		$a_80_0 = {6f 63 70 69 2e 63 6f 6d 2e 6d 79 2f 73 6d 6f 6b 65 2f 6c 6f 61 64 65 72 2f 75 70 6c 6f 61 64 73 2f } //ocpi.com.my/smoke/loader/uploads/  0a 00 
		$a_80_1 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 31 67 67 38 30 6c 2f 4e 78 69 69 73 6e 5f 56 74 63 78 6a 68 6c 70 2e 62 6d 70 } //transfer.sh/get/1gg80l/Nxiisn_Vtcxjhlp.bmp  0a 00 
		$a_80_2 = {69 6e 6f 78 2d 73 6d 61 72 74 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 4e 7a 61 63 63 7a 62 2e 70 6e 67 } //inox-smart.com/wp-admin/Nzacczb.png  0a 00 
		$a_80_3 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 35 57 7a 6b 56 72 2f 5a 76 68 69 61 78 70 6d 73 5f 55 77 66 69 73 69 6b 62 2e 62 6d 70 } //transfer.sh/get/5WzkVr/Zvhiaxpms_Uwfisikb.bmp  03 00 
		$a_81_4 = {47 65 74 41 73 73 65 6d 62 6c 69 65 73 } //03 00 
		$a_81_5 = {54 6f 53 74 72 69 6e 67 } //02 00 
		$a_81_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //02 00 
		$a_81_7 = {47 65 74 54 79 70 65 73 } //01 00 
		$a_81_8 = {47 65 74 54 79 70 65 } //01 00 
		$a_81_9 = {49 6e 76 6f 6b 65 } //01 00 
		$a_81_10 = {47 65 74 4d 65 74 68 6f 64 } //00 00 
	condition:
		any of ($a_*)
 
}