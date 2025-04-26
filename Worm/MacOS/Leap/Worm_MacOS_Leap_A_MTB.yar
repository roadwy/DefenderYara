
rule Worm_MacOS_Leap_A_MTB{
	meta:
		description = "Worm:MacOS/Leap.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 61 70 70 68 6f 6f 6b 5f 70 72 6f 6a 65 63 74 2f 61 70 70 68 6f 6f 6b 2e 6d } //1 /tmp/apphook_project/apphook.m
		$a_00_1 = {2f 74 6d 70 2f 6c 61 74 65 73 74 70 69 63 73 2e 67 7a } //1 /tmp/latestpics.gz
		$a_00_2 = {78 5f 69 6e 69 74 4f 75 74 67 6f 69 6e 67 57 69 74 68 53 65 6e 64 65 72 3a 6f 75 74 67 6f 69 6e 67 46 69 6c 65 3a 63 68 61 74 3a } //1 x_initOutgoingWithSender:outgoingFile:chat:
		$a_00_3 = {78 5f 61 6e 79 41 63 74 69 76 65 46 69 6c 65 54 72 61 6e 73 66 65 72 73 } //1 x_anyActiveFileTransfers
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}