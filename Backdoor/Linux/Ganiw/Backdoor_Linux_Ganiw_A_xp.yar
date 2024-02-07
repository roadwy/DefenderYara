
rule Backdoor_Linux_Ganiw_A_xp{
	meta:
		description = "Backdoor:Linux/Ganiw.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 55 70 64 61 74 65 42 69 6c 6c } //01 00  CUpdateBill
		$a_01_1 = {43 41 74 74 61 63 6b 55 64 70 } //01 00  CAttackUdp
		$a_01_2 = {43 55 70 64 61 74 65 47 61 74 65 73 } //01 00  CUpdateGates
		$a_01_3 = {43 46 61 6b 65 44 65 74 65 63 74 50 61 79 6c 6f 61 64 } //01 00  CFakeDetectPayload
		$a_01_4 = {43 41 74 74 61 63 6b 43 63 } //00 00  CAttackCc
	condition:
		any of ($a_*)
 
}