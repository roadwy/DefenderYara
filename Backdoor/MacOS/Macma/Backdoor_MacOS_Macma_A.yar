
rule Backdoor_MacOS_Macma_A{
	meta:
		description = "Backdoor:MacOS/Macma.A,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 63 6f 6d 2e 55 73 65 72 41 67 65 6e 74 2e [0-10] 2e 70 6c 69 73 74 } //2
		$a_00_1 = {73 65 6e 64 20 43 44 44 53 4d 61 63 53 65 61 72 63 68 46 69 6c 65 20 74 61 73 6b 69 64 20 25 64 20 2c 6d 5f 53 72 63 48 6f 73 74 20 25 64 2c 6d 5f 53 72 63 43 6c 69 65 6e 74 20 25 64 20 72 65 74 20 25 64 20 76 65 63 20 25 64 } //2 send CDDSMacSearchFile taskid %d ,m_SrcHost %d,m_SrcClient %d ret %d vec %d
		$a_00_2 = {43 44 44 53 52 65 71 75 65 73 74 44 6f 77 6e 6c 6f 61 64 3a 6d 5f 6e 54 61 73 6b 49 44 3a 25 64 2c 6d 5f 73 74 72 52 65 6d 6f 74 65 46 69 6c 65 3a 25 73 2c 6d 5f 73 74 72 4c 6f 63 61 6c 53 61 76 65 41 73 3a 25 73 } //2 CDDSRequestDownload:m_nTaskID:%d,m_strRemoteFile:%s,m_strLocalSaveAs:%s
		$a_00_3 = {28 24 31 3d 3d 22 00 22 29 20 73 79 73 74 65 6d 28 22 6b 69 6c 6c 20 2d 39 20 22 24 32 29 3b 7d 27 00 2e 6b 69 6c 6c 63 68 65 63 6b 65 72 5f 00 22 29 } //1
		$a_00_4 = {43 44 44 53 53 63 72 65 65 6e 43 61 70 74 75 72 65 50 61 72 61 6d 65 74 65 72 52 65 71 75 65 73 74 } //1 CDDSScreenCaptureParameterRequest
		$a_00_5 = {43 44 44 53 4d 61 63 46 69 6c 65 4c 69 73 74 52 65 70 6c 79 } //1 CDDSMacFileListReply
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}