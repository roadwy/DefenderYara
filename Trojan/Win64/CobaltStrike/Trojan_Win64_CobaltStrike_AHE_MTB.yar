
rule Trojan_Win64_CobaltStrike_AHE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_81_0 = {5b 49 4e 46 4f 5d 20 52 75 6e 4d 61 69 6e 4c 6f 67 69 63 } //10 [INFO] RunMainLogic
		$a_81_1 = {5b 49 4e 46 4f 5d 20 43 61 70 74 75 72 65 53 65 63 75 72 65 53 63 72 65 65 6e } //20 [INFO] CaptureSecureScreen
		$a_81_2 = {5b 49 4e 46 4f 5d 20 45 78 65 63 75 74 69 6e 67 20 72 65 73 74 61 72 74 20 63 6f 6d 6d 61 6e 64 } //30 [INFO] Executing restart command
		$a_81_3 = {5b 49 4e 46 4f 5d 20 45 6e 61 62 6c 65 20 41 75 74 6f 41 64 6d 69 6e 4c 6f 67 6f 6e } //40 [INFO] Enable AutoAdminLogon
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*20+(#a_81_2  & 1)*30+(#a_81_3  & 1)*40) >=100
 
}