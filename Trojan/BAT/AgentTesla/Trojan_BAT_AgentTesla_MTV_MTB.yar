
rule Trojan_BAT_AgentTesla_MTV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 10 00 00 "
		
	strings :
		$a_80_0 = {45 78 65 63 75 74 65 4e 6f 6e 51 75 65 72 79 } //ExecuteNonQuery  2
		$a_80_1 = {42 69 64 69 43 61 74 65 67 6f 72 79 } //BidiCategory  2
		$a_80_2 = {44 62 44 61 74 61 41 64 61 70 74 65 72 } //DbDataAdapter  2
		$a_80_3 = {53 71 6c 44 61 74 61 41 64 61 70 74 65 72 } //SqlDataAdapter  2
		$a_80_4 = {53 71 6c 44 61 74 61 52 65 61 64 65 72 } //SqlDataReader  2
		$a_80_5 = {45 78 65 63 75 74 65 52 65 61 64 65 72 } //ExecuteReader  2
		$a_80_6 = {42 69 74 6d 61 70 } //Bitmap  2
		$a_80_7 = {53 71 6c 43 6f 6e 6e 65 63 74 69 6f 6e } //SqlConnection  2
		$a_80_8 = {4d 69 6e 6f 72 56 65 72 73 69 6f 6e } //MinorVersion  2
		$a_80_9 = {47 65 74 50 69 78 65 6c } //GetPixel  2
		$a_80_10 = {47 65 74 54 79 70 65 } //GetType  2
		$a_80_11 = {4c 69 6f 6e 5f 4d 61 74 63 68 5f 45 6d 70 6c 6f 79 65 65 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d } //Lion_Match_Employee_Management_System  2
		$a_80_12 = {4c 69 6f 6e 5f 4d 61 74 63 68 5f 45 6d 70 6c 6f 79 65 65 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 48 42 54 } //Lion_Match_Employee_Management_System.HBT  2
		$a_80_13 = {53 5a 47 65 6e 65 72 69 63 } //SZGeneric  2
		$a_80_14 = {4c 69 6f 6e 5f 4d 61 74 63 68 5f 45 6d 70 6c 6f 79 65 65 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 52 65 73 6f 75 72 63 65 73 } //Lion_Match_Employee_Management_System.Resources  2
		$a_80_15 = {74 78 74 70 61 73 73 77 6f 72 64 } //txtpassword  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2+(#a_80_7  & 1)*2+(#a_80_8  & 1)*2+(#a_80_9  & 1)*2+(#a_80_10  & 1)*2+(#a_80_11  & 1)*2+(#a_80_12  & 1)*2+(#a_80_13  & 1)*2+(#a_80_14  & 1)*2+(#a_80_15  & 1)*2) >=30
 
}