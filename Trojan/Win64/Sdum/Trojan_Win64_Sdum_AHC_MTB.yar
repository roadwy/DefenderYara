
rule Trojan_Win64_Sdum_AHC_MTB{
	meta:
		description = "Trojan:Win64/Sdum.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_81_0 = {57 69 6e 64 6f 77 73 20 43 6f 6d 70 6f 6e 65 6e 74 20 55 70 64 61 74 65 20 53 65 72 76 69 63 65 } //10 Windows Component Update Service
		$a_81_1 = {57 69 6e 64 6f 77 73 20 53 6f 66 74 77 61 72 65 20 46 6f 75 6e 64 61 74 69 6f 6e } //20 Windows Software Foundation
		$a_81_2 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 20 22 24 57 53 20 3d 20 4e 65 77 2d 4f 62 6a 65 63 74 20 2d 43 6f 6d 4f 62 6a 65 63 74 20 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 3b 20 24 53 43 20 3d 20 24 57 53 2e 43 72 65 61 74 65 53 68 6f 72 74 63 75 74 28 } //30 powershell -WindowStyle Hidden -Command "$WS = New-Object -ComObject WScript.Shell; $SC = $WS.CreateShortcut(
		$a_81_3 = {4d 69 63 72 6f 73 6f 66 74 45 64 67 65 55 70 64 61 74 65 2e 6c 6e 6b } //40 MicrosoftEdgeUpdate.lnk
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*20+(#a_81_2  & 1)*30+(#a_81_3  & 1)*40) >=100
 
}