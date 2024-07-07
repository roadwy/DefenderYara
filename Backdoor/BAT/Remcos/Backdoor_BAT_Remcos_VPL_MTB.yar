
rule Backdoor_BAT_Remcos_VPL_MTB{
	meta:
		description = "Backdoor:BAT/Remcos.VPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0e 00 00 "
		
	strings :
		$a_81_0 = {24 31 36 32 61 32 34 35 63 2d 31 37 32 37 2d 34 62 34 65 2d 61 62 36 32 2d 64 37 32 37 37 61 66 35 61 37 32 33 } //1 $162a245c-1727-4b4e-ab62-d7277af5a723
		$a_01_1 = {53 00 65 00 72 00 76 00 65 00 72 00 4e 00 61 00 6d 00 65 00 5c 00 73 00 65 00 72 00 76 00 65 00 72 00 4e 00 61 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //1 ServerName\serverName.txt
		$a_81_2 = {4e 75 72 73 65 72 79 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 73 69 67 6e 49 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Nursery_Management_System.signIn.resources
		$a_81_3 = {4e 75 72 73 65 72 79 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 73 69 67 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Nursery_Management_System.sign.resources
		$a_81_4 = {4e 75 72 73 65 72 79 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 73 69 67 6e 55 70 2e 72 65 73 6f 75 72 63 65 73 } //1 Nursery_Management_System.signUp.resources
		$a_81_5 = {4e 75 72 73 65 72 79 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 41 6e 61 6c 79 74 69 63 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Nursery_Management_System.Analytics.resources
		$a_81_6 = {4e 75 72 73 65 72 79 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Nursery_Management_System.Properties.Resources.resources
		$a_81_7 = {4e 75 72 73 65 72 79 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 63 68 69 6c 64 44 61 69 6c 79 44 65 74 61 69 6c 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Nursery_Management_System.childDailyDetails.resources
		$a_81_8 = {4e 75 72 73 65 72 79 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 61 64 6d 69 6e 50 65 6e 64 69 6e 67 52 65 71 75 65 73 74 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Nursery_Management_System.adminPendingRequests.resources
		$a_81_9 = {4c 69 6e 6b 4c 61 62 65 6c 4c 69 6e 6b 43 6c 69 63 6b 65 64 45 76 65 6e 74 41 72 67 73 } //1 LinkLabelLinkClickedEventArgs
		$a_81_10 = {67 65 74 5f 4d 4e 42 56 43 58 43 5a 42 47 59 48 } //1 get_MNBVCXCZBGYH
		$a_81_11 = {6f 70 5f 45 71 75 61 6c 69 74 79 } //1 op_Equality
		$a_81_12 = {6f 70 5f 49 6e 65 71 75 61 6c 69 74 79 } //1 op_Inequality
		$a_81_13 = {57 72 61 70 4e 6f 6e 45 78 63 65 70 74 69 6f 6e 54 68 72 6f 77 73 } //1 WrapNonExceptionThrows
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1) >=14
 
}