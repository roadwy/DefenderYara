
rule Trojan_BAT_CryptInject_PO_MTB{
	meta:
		description = "Trojan:BAT/CryptInject.PO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {24 35 33 35 39 31 36 66 36 2d 65 63 32 30 2d 34 37 61 33 2d 61 61 33 63 2d 62 38 37 31 30 63 66 64 36 38 31 32 } //1 $535916f6-ec20-47a3-aa3c-b8710cfd6812
		$a_81_1 = {43 6c 69 6e 69 63 20 4d 61 6e 61 67 65 6d 65 6e 74 20 53 79 73 74 65 6d } //1 Clinic Management System
		$a_81_2 = {43 6c 69 6e 69 63 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 66 72 6d 5f 50 61 74 69 65 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Clinic_Management_System.frm_Patient.resources
		$a_81_3 = {43 6c 69 6e 69 63 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 4d 6f 61 66 61 4d 65 73 73 61 67 65 42 6f 78 2e 72 65 73 6f 75 72 63 65 73 } //1 Clinic_Management_System.MoafaMessageBox.resources
		$a_81_4 = {43 6c 69 6e 69 63 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 53 79 73 74 65 6d 2e 66 72 6d 5f 41 64 64 5f 50 61 74 69 65 6e 74 2e 72 65 73 6f 75 72 63 65 73 } //1 Clinic_Management_System.frm_Add_Patient.resources
		$a_81_5 = {67 65 74 5f 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 71 } //1 get_qqqqqqqqqqqqqqqqqqqqqqqqqqqqq
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}