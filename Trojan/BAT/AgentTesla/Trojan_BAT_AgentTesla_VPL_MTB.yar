
rule Trojan_BAT_AgentTesla_VPL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 "
		
	strings :
		$a_81_0 = {24 35 39 61 66 30 32 31 31 2d 66 33 36 36 2d 34 65 36 65 2d 61 64 39 31 2d 33 33 30 33 33 36 63 34 39 38 30 63 } //1 $59af0211-f366-4e6e-ad91-330336c4980c
		$a_81_1 = {68 61 34 3d 79 3d 7b 4b 27 61 2a 4a 27 62 33 4b 27 3e 26 46 5f 28 2b 5f 7d 29 36 25 49 76 70 70 70 22 3c 70 70 70 70 71 63 66 66 7a 66 7c 70 70 70 70 45 7b 78 78 2a 72 64 7a 23 7e 27 26 24 70 70 70 70 70 44 29 7d 64 33 5f 32 65 38 76 33 73 40 27 24 21 67 3f 38 24 44 7c 3b 47 25 70 3d 43 7e 35 7d 76 41 49 3e } //1 ha4=y={K'a*J'b3K'>&F_(+_})6%Ivppp"<ppppqcffzf|ppppE{xx*rdz#~'&$pppppD)}d3_2e8v3s@'$!g?8$D|;G%p=C~5}vAI>
		$a_81_2 = {35 62 49 73 68 5a 32 38 43 66 76 21 3c 45 25 7b 73 76 68 42 63 75 62 7b } //1 5bIshZ28Cfv!<E%{svhBcub{
		$a_81_3 = {41 64 64 55 73 65 72 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d 5f 43 6c 69 63 6b } //1 AddUserToolStripMenuItem_Click
		$a_81_4 = {44 65 6c 65 74 65 55 73 65 72 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d 5f 43 6c 69 63 6b } //1 DeleteUserToolStripMenuItem_Click
		$a_81_5 = {41 4d 53 2e 4d 79 } //1 AMS.My
		$a_81_6 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
		$a_81_7 = {53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 } //1 System.Security.Cryptography
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_9 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_10 = {41 4d 53 2e 41 64 64 5f 43 6f 75 72 73 65 5f 54 65 61 63 68 65 72 5f 53 74 75 64 65 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //1 AMS.Add_Course_Teacher_Student.resources
		$a_81_11 = {41 4d 53 2e 41 64 64 55 73 65 72 46 72 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 AMS.AddUserFrm.resources
		$a_81_12 = {41 4d 53 2e 41 6e 73 69 43 68 61 72 4d 61 72 73 68 61 6c 65 72 2e 72 65 73 6f 75 72 63 65 73 } //1 AMS.AnsiCharMarshaler.resources
		$a_81_13 = {41 4d 53 2e 43 6f 75 72 73 65 5f 52 65 67 69 73 74 72 61 74 69 6f 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 AMS.Course_Registration.resources
		$a_81_14 = {41 4d 53 2e 47 50 41 5f 41 63 61 64 65 6d 69 63 5f 48 69 73 74 6f 72 79 5f 4c 6f 6f 6b 5f 55 70 2e 72 65 73 6f 75 72 63 65 73 } //1 AMS.GPA_Academic_History_Look_Up.resources
		$a_81_15 = {41 4d 53 2e 4c 6f 67 49 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 AMS.LogIn.resources
		$a_81_16 = {41 4d 53 2e 4d 61 69 6e 5f 4d 65 6e 75 2e 72 65 73 6f 75 72 63 65 73 } //1 AMS.Main_Menu.resources
		$a_81_17 = {41 4d 53 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 AMS.Resources.resources
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1+(#a_81_16  & 1)*1+(#a_81_17  & 1)*1) >=18
 
}