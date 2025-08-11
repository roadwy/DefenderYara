
rule Trojan_MacOS_PasivRobber_C_MTB{
	meta:
		description = "Trojan:MacOS/PasivRobber.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 58 52 6f 62 62 65 72 } //1 WXRobber
		$a_01_1 = {63 6f 6d 2e 6d 79 61 6d 2e 70 6c 69 73 74 } //1 com.myam.plist
		$a_01_2 = {47 65 74 53 63 72 65 65 6e 53 68 6f 74 } //1 GetScreenShot
		$a_01_3 = {6c 69 62 49 4d 4b 65 79 54 6f 6f 6c } //1 libIMKeyTool
		$a_01_4 = {52 65 6d 6f 74 65 4d 73 67 4d 61 6e 61 67 65 72 } //1 RemoteMsgManager
		$a_01_5 = {47 65 74 43 6c 69 70 62 6f 61 72 64 49 6e 66 6f 73 } //1 GetClipboardInfos
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}