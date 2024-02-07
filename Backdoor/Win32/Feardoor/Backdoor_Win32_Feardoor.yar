
rule Backdoor_Win32_Feardoor{
	meta:
		description = "Backdoor:Win32/Feardoor,SIGNATURE_TYPE_PEHSTR_EXT,09 00 07 00 0c 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 46 65 61 72 52 41 54 5c 53 65 72 76 65 72 5c } //01 00  \FearRAT\Server\
		$a_00_1 = {5c 66 65 61 72 5c 53 65 72 76 65 72 5c } //01 00  \fear\Server\
		$a_01_2 = {3a 67 6f 63 68 61 74 3f 72 6f 6f 6d 6e 61 6d 65 3d } //01 00  :gochat?roomname=
		$a_01_3 = {43 68 61 74 20 52 6f 6f 6d 3a } //01 00  Chat Room:
		$a_01_4 = {53 65 74 20 43 44 41 75 64 69 6f 20 44 6f 6f 72 } //01 00  Set CDAudio Door
		$a_01_5 = {5f 4f 73 63 61 72 5f 49 63 6f 6e 42 74 6e } //01 00  _Oscar_IconBtn
		$a_01_6 = {41 49 4d 5f 49 4d 65 73 73 61 67 65 } //01 00  AIM_IMessage
		$a_01_7 = {4f 6c 69 76 65 74 74 69 20 31 30 32 } //01 00  Olivetti 102
		$a_01_8 = {73 65 6e 64 74 78 74 66 69 6c 65 } //01 00  sendtxtfile
		$a_00_9 = {39 61 64 36 2d 30 30 38 30 63 37 65 37 62 37 38 64 } //01 00  9ad6-0080c7e7b78d
		$a_01_10 = {46 45 41 52 20 2d 20 53 45 52 56 45 52 } //01 00  FEAR - SERVER
		$a_01_11 = {5f 4f 73 63 61 72 5f 50 65 72 73 69 73 74 61 6e 74 43 6f 6d 62 6f } //00 00  _Oscar_PersistantCombo
	condition:
		any of ($a_*)
 
}