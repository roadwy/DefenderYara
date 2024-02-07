
rule TrojanSpy_AndroidOS_Pegasus_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Pegasus.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 64 65 63 72 79 70 74 73 74 72 69 6e 67 6d 61 6e 61 67 65 72 } //01 00  com/decryptstringmanager
		$a_01_1 = {6e 65 74 5f 76 74 70 5f 63 61 6c 6c 5f 73 74 61 74 65 5f 69 6e 66 6f } //01 00  net_vtp_call_state_info
		$a_01_2 = {63 68 6d 6f 64 4f 6e 65 43 6f 6d 6d 61 6e 64 } //01 00  chmodOneCommand
		$a_01_3 = {41 47 45 4e 54 5f 45 58 46 49 4c 54 52 41 54 49 4f 4e 5f 48 45 41 44 45 52 } //01 00  AGENT_EXFILTRATION_HEADER
		$a_01_4 = {73 65 6e 64 44 61 74 61 53 6d 73 42 79 4d 61 6e 61 67 65 72 } //00 00  sendDataSmsByManager
	condition:
		any of ($a_*)
 
}