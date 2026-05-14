
rule PWS_Win64_CrystalX_C_MTB{
	meta:
		description = "PWS:Win64/CrystalX.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 08 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 53 74 65 61 6c 65 72 } //5 runStealer
		$a_01_1 = {73 74 65 61 6c 53 63 72 65 65 6e 73 68 6f 74 } //5 stealScreenshot
		$a_01_2 = {73 74 65 61 6c 55 73 65 72 49 6e 66 6f } //5 stealUserInfo
		$a_01_3 = {73 74 65 61 6c 44 69 73 63 6f 72 64 54 6f 6b 65 6e 73 } //5 stealDiscordTokens
		$a_01_4 = {73 74 65 61 6c 42 72 6f 77 73 65 72 73 } //5 stealBrowsers
		$a_01_5 = {67 65 74 43 6c 69 70 62 6f 61 72 64 54 65 78 74 } //5 getClipboardText
		$a_01_6 = {73 74 61 72 74 57 65 62 63 61 6d } //5 startWebcam
		$a_01_7 = {73 74 61 72 74 4d 69 63 } //5 startMic
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5) >=40
 
}