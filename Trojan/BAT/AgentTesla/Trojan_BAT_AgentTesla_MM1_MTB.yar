
rule Trojan_BAT_AgentTesla_MM1_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MM1!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {24 39 32 38 61 66 61 32 30 2d 63 64 61 61 2d 34 34 39 33 2d 62 33 39 61 2d 33 33 32 31 36 63 38 31 33 39 35 32 } //1 $928afa20-cdaa-4493-b39a-33216c813952
		$a_01_1 = {67 65 74 5f 74 65 6e 64 6f 63 67 69 61 } //1 get_tendocgia
		$a_01_2 = {72 74 78 74 62 5f 64 69 61 63 68 69 } //1 rtxtb_diachi
		$a_01_3 = {51 4c 54 56 2e 66 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 QLTV.frmMain.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}