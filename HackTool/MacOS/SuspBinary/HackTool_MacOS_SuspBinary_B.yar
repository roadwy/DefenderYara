
rule HackTool_MacOS_SuspBinary_B{
	meta:
		description = "HackTool:MacOS/SuspBinary.B,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 61 70 70 6c 65 2e 54 43 43 2f 54 43 43 2e 64 62 20 22 73 65 6c 65 63 74 20 2a 20 66 72 6f 6d 20 61 63 63 65 73 73 20 77 68 65 72 65 20 73 65 72 76 69 63 65 3d 27 6b 54 43 43 53 65 72 76 69 63 65 53 79 73 74 65 6d 50 6f 6c 69 63 79 41 6c 6c 46 69 6c 65 73 27 } //1 com.apple.TCC/TCC.db "select * from access where service='kTCCServiceSystemPolicyAllFiles'
		$a_00_1 = {63 72 6f 6e 74 61 62 20 2d 6c 20 7c 20 65 63 68 6f 20 22 25 73 22 20 7c 20 63 72 6f 6e 74 61 62 20 2d } //1 crontab -l | echo "%s" | crontab -
		$a_00_2 = {43 79 6d 75 6c 61 74 65 45 44 52 53 63 65 6e 61 72 69 6f 45 78 65 63 75 74 6f 72 } //1 CymulateEDRScenarioExecutor
		$a_00_3 = {65 64 72 5f 61 74 74 61 63 6b 73 5f 70 61 74 68 } //1 edr_attacks_path
		$a_00_4 = {73 75 20 72 6f 6f 74 20 2d 63 } //1 su root -c
		$a_00_5 = {43 59 4d 55 4c 41 54 45 5f 45 44 52 5f 4d 55 54 45 58 } //1 CYMULATE_EDR_MUTEX
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}