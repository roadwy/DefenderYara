
rule Backdoor_Linux_GTPDoor_A_MTB{
	meta:
		description = "Backdoor:Linux/GTPDoor.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,08 00 08 00 05 00 00 05 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 48 98 48 89 c1 48 03 4d c8 0f b6 45 fb 48 03 45 e8 0f b6 10 8b 45 fc 48 98 48 03 45 d8 0f b6 00 31 d0 88 01 80 45 fb 01 83 45 fc 01 0f b7 45 d4 3b 45 fc 7f 90 01 01 0f b7 45 d4 90 00 } //05 00 
		$a_02_1 = {8b 45 fc 89 c1 03 4d 18 0f b6 45 fb 03 45 08 0f b6 10 8b 45 fc 03 45 10 0f b6 00 31 d0 88 01 80 45 fb 01 83 45 fc 01 0f b7 45 e8 3b 45 fc 7f 90 01 01 0f b7 45 e8 90 00 } //01 00 
		$a_01_2 = {6d 79 44 65 63 72 79 70 74 46 75 6e } //01 00  myDecryptFun
		$a_01_3 = {72 65 6d 6f 74 65 45 78 65 63 } //01 00  remoteExec
		$a_01_4 = {73 65 6e 64 52 65 73 75 6c 74 32 50 65 65 72 } //00 00  sendResult2Peer
	condition:
		any of ($a_*)
 
}