
rule HackTool_AndroidOS_Arpspoof_A_MTB{
	meta:
		description = "HackTool:AndroidOS/Arpspoof.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 61 6c 6c 20 61 72 70 73 70 6f 6f 66 } //1 killall arpspoof
		$a_01_1 = {41 72 70 73 70 6f 6f 66 53 65 72 76 69 63 65 } //1 ArpspoofService
		$a_01_2 = {53 70 6f 6f 66 69 6e 67 20 77 61 73 20 69 6e 74 65 72 72 75 70 74 65 64 } //1 Spoofing was interrupted
		$a_01_3 = {61 72 70 73 70 6f 6f 66 2f 52 6f 6f 74 41 63 63 65 73 73 } //1 arpspoof/RootAccess
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}