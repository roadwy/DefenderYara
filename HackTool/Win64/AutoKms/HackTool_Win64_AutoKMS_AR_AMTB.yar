
rule HackTool_Win64_AutoKMS_AR_AMTB{
	meta:
		description = "HackTool:Win64/AutoKMS.AR!AMTB,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 64 20 4b 4d 53 20 64 61 74 61 20 66 69 6c 65 20 76 65 72 73 69 6f 6e 20 25 75 2e 25 75 20 25 73 } //1 Read KMS data file version %u.%u %s
		$a_01_1 = {3c 3c 3c 20 49 6e 63 6f 6d 69 6e 67 20 4b 4d 53 20 72 65 71 75 65 73 74 } //1 <<< Incoming KMS request
		$a_01_2 = {4b 65 79 20 4d 61 6e 61 67 65 6d 65 6e 74 20 53 65 72 76 65 72 } //1 Key Management Server
		$a_01_3 = {4b 4d 53 20 68 6f 73 74 20 63 75 72 72 65 6e 74 20 61 63 74 69 76 65 20 63 6c 69 65 6e 74 73 20 3a 20 25 75 } //1 KMS host current active clients : %u
		$a_01_4 = {41 63 74 69 76 61 74 69 6f 6e 20 69 6e 74 65 72 76 61 6c 20 70 6f 6c 69 63 79 20 20 20 20 20 20 3a 20 25 75 } //1 Activation interval policy      : %u
		$a_01_5 = {4b 4d 53 20 68 6f 73 74 20 48 61 72 64 77 61 72 65 20 49 44 20 20 20 20 20 20 20 20 20 20 20 20 3a 20 25 30 31 36 49 36 34 58 } //1 KMS host Hardware ID            : %016I64X
		$a_01_6 = {57 61 72 6e 69 6e 67 3a 20 54 72 61 6e 73 66 65 72 20 73 79 6e 74 61 78 20 25 73 20 64 6f 65 73 20 6e 6f 74 20 73 75 70 70 6f 72 74 20 4b 4d 53 20 61 63 74 69 76 61 74 69 6f 6e } //1 Warning: Transfer syntax %s does not support KMS activation
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}