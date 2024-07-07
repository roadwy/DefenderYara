
rule HackTool_MacOS_Vortex_D_MTB{
	meta:
		description = "HackTool:MacOS/Vortex.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_03_0 = {2f 4f 64 79 73 73 65 79 2f 4f 64 79 73 73 65 79 2f 65 78 70 6c 6f 69 74 90 02 15 2e 63 90 00 } //1
		$a_01_1 = {2f 6f 64 79 73 73 65 79 2f 6c 61 75 6e 63 68 6a 61 69 6c 62 72 65 61 6b } //1 /odyssey/launchjailbreak
		$a_01_2 = {2f 6f 64 79 73 73 65 79 2f 61 6d 66 69 64 65 62 69 6c 69 74 61 74 65 2e 70 6c 69 73 74 } //1 /odyssey/amfidebilitate.plist
		$a_01_3 = {6f 72 67 2e 63 6f 6f 6c 73 74 61 72 2e 6a 61 69 6c 62 72 65 61 6b 64 } //1 org.coolstar.jailbreakd
		$a_01_4 = {52 52 52 52 65 61 74 72 6d 70 65 20 39 61 66 69 6f 61 73 66 } //1 RRRReatrmpe 9afioasf
		$a_01_5 = {74 66 70 30 } //1 tfp0
		$a_01_6 = {74 61 72 64 79 30 6e } //1 tardy0n
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}