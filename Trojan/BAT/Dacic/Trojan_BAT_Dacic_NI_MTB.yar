
rule Trojan_BAT_Dacic_NI_MTB{
	meta:
		description = "Trojan:BAT/Dacic.NI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {66 62 30 37 38 64 62 64 2d 62 39 38 38 2d 34 30 62 39 2d 62 38 62 30 2d 39 32 37 32 63 37 33 66 36 65 65 33 } //2 fb078dbd-b988-40b9-b8b0-9272c73f6ee3
		$a_81_1 = {43 50 55 5f 53 63 68 65 64 75 6c 69 6e 67 } //1 CPU_Scheduling
		$a_81_2 = {50 72 6f 63 65 73 73 65 73 53 63 68 65 64 75 6c 69 6e 67 } //1 ProcessesScheduling
		$a_81_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_4 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //1 NetworkCredential
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}