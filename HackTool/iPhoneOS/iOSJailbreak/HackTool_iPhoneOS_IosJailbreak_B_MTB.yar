
rule HackTool_iPhoneOS_IosJailbreak_B_MTB{
	meta:
		description = "HackTool:iPhoneOS/IosJailbreak.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 6f 6f 6b 69 6e 67 20 50 61 79 6c 6f 61 64 } //1 Hooking Payload
		$a_01_1 = {4f 6e 65 4c 6f 6c 31 6e } //1 OneLol1n
		$a_01_2 = {2f 70 70 72 69 76 61 72 2f 6d 62 72 61 72 79 2f 43 61 72 69 76 61 61 74 65 2f 6f 62 69 6c 65 2f 4c 69 2f 63 6f 6d 2e 73 61 75 72 69 6b 2e 74 65 2f 76 73 2f 43 79 64 69 61 2e 61 70 70 } //1 /pprivar/mbrary/Carivaate/obile/Li/com.saurik.te/vs/Cydia.app
		$a_01_3 = {69 70 77 6e 64 65 72 } //1 ipwnder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}