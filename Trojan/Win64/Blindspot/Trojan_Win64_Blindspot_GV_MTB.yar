
rule Trojan_Win64_Blindspot_GV_MTB{
	meta:
		description = "Trojan:Win64/Blindspot.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 "
		
	strings :
		$a_01_0 = {42 6c 69 6e 64 73 70 6f 74 20 41 67 65 6e 74 } //1 Blindspot Agent
		$a_01_1 = {6d 61 69 6e 2e 42 6c 69 6e 64 73 70 6f 74 50 61 79 6c 6f 61 64 } //3 main.BlindspotPayload
		$a_01_2 = {6d 61 69 6e 2e 52 75 6e 6e 69 6e 67 43 61 6d 70 61 69 67 6e } //1 main.RunningCampaign
		$a_01_3 = {6d 61 69 6e 2e 62 69 6e 64 61 74 61 46 69 6c 65 49 6e 66 6f } //1 main.bindataFileInfo
		$a_01_4 = {6d 61 69 6e 2e 44 65 63 6f 64 65 64 4f 75 74 70 75 74 } //1 main.DecodedOutput
		$a_01_5 = {6d 61 69 6e 2e 53 63 72 65 65 6e 73 68 6f 74 } //1 main.Screenshot
		$a_01_6 = {6d 61 69 6e 2e 63 6f 6e 66 46 69 6c 65 3d 62 6c 69 6e 64 73 70 6f 74 2d 61 67 65 6e 74 2e 63 6f 6e 66 } //3 main.confFile=blindspot-agent.conf
		$a_01_7 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 65 64 56 46 53 3d 62 6c 69 6e 64 73 70 6f 74 2e 7a 69 70 } //3 main.encryptedVFS=blindspot.zip
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3) >=14
 
}