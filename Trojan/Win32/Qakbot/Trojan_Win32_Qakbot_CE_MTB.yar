
rule Trojan_Win32_Qakbot_CE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_81_0 = {4c 6f 61 64 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 41 } //3 LoadKeyboardLayoutA
		$a_81_1 = {4d 65 73 73 61 67 65 42 65 65 70 } //3 MessageBeep
		$a_81_2 = {6d 41 63 79 76 69 35 78 } //3 mAcyvi5x
		$a_81_3 = {43 4a 77 76 65 39 79 } //3 CJwve9y
		$a_81_4 = {42 47 67 66 4c 44 4e 5f 4b 58 5f 55 49 } //3 BGgfLDN_KX_UI
		$a_81_5 = {74 72 61 79 6e 6f 74 69 66 79 } //3 traynotify
		$a_81_6 = {43 6c 69 65 6e 74 54 6f 53 63 72 65 65 6e } //3 ClientToScreen
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3+(#a_81_5  & 1)*3+(#a_81_6  & 1)*3) >=21
 
}
rule Trojan_Win32_Qakbot_CE_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {52 50 38 4c 43 68 65 63 6b 53 69 67 6e 61 74 75 72 65 } //1 RP8LCheckSignature
		$a_01_1 = {52 65 62 50 42 6c 65 6e 64 41 6c 70 68 61 } //1 RebPBlendAlpha
		$a_01_2 = {52 65 62 50 43 6c 65 61 6e 75 70 54 72 61 6e 73 70 61 72 65 6e 74 41 72 65 61 } //1 RebPCleanupTransparentArea
		$a_01_3 = {52 65 62 50 43 6f 6e 66 69 67 49 6e 69 74 49 6e 74 65 72 6e 61 6c } //1 RebPConfigInitInternal
		$a_01_4 = {52 65 62 50 44 65 63 6f 64 65 41 52 47 42 49 6e 74 6f } //1 RebPDecodeARGBInto
		$a_01_5 = {52 65 62 50 44 65 63 6f 64 65 59 55 56 49 6e 74 6f } //1 RebPDecodeYUVInto
		$a_01_6 = {52 65 62 50 45 6e 63 6f 64 65 4c 6f 73 73 6c 65 73 73 42 47 52 } //1 RebPEncodeLosslessBGR
		$a_01_7 = {52 65 62 50 47 65 74 44 65 63 6f 64 65 72 56 65 72 73 69 6f 6e } //1 RebPGetDecoderVersion
		$a_01_8 = {52 65 62 50 49 6e 69 74 44 65 63 6f 64 65 72 43 6f 6e 66 69 67 49 6e 74 65 72 6e 61 6c } //1 RebPInitDecoderConfigInternal
		$a_01_9 = {52 65 62 50 50 69 63 74 75 72 65 41 52 47 42 54 6f 59 55 56 41 44 69 74 68 65 72 65 64 } //1 RebPPictureARGBToYUVADithered
		$a_01_10 = {52 65 62 50 4d 65 6d 6f 72 79 57 72 69 74 65 72 49 6e 69 74 } //1 RebPMemoryWriterInit
		$a_01_11 = {52 65 62 50 50 69 63 74 75 72 65 59 55 56 41 54 6f 41 52 47 42 } //1 RebPPictureYUVAToARGB
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}