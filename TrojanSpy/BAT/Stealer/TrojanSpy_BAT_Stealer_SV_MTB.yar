
rule TrojanSpy_BAT_Stealer_SV_MTB{
	meta:
		description = "TrojanSpy:BAT/Stealer.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 57 52 49 54 45 5f 55 52 4c } //2 $WRITE_URL
		$a_81_1 = {62 69 68 6a 66 6f 73 69 68 75 77 67 69 67 68 75 7a 68 64 63 2e 74 61 77 6f 72 33 33 39 37 31 2e 77 6f 72 6b 65 72 73 2e 64 65 76 } //2 bihjfosihuwgighuzhdc.tawor33971.workers.dev
		$a_01_2 = {24 73 63 72 65 65 6e 73 68 6f 74 5f 70 61 74 68 20 3d 20 22 24 65 6e 76 3a 55 53 45 52 50 52 4f 46 49 4c 45 5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 5c 73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //2 $screenshot_path = "$env:USERPROFILE\AppData\Local\Temp\screenshot.png
		$a_81_3 = {72 61 74 6e 65 77 2e 70 73 31 } //1 ratnew.ps1
		$a_81_4 = {67 68 68 68 68 2e 70 73 31 } //1 ghhhh.ps1
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_01_2  & 1)*2+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=7
 
}