
rule Backdoor_BAT_WebShell_GMH_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 70 5f 67 6c 6f 62 61 6c 2e 61 73 61 78 2e 79 78 36 61 72 65 71 77 } //01 00 
		$a_01_1 = {53 79 73 74 65 6d 2e 54 65 78 74 } //01 00 
		$a_01_2 = {72 6f 6f 74 5c 38 35 30 62 38 32 38 37 5c 61 65 32 64 33 66 65 39 } //01 00 
		$a_80_3 = {43 72 6d 4d 61 6e 61 67 65 6d 65 6e 74 2f 4d 65 6d 62 65 72 4d 61 6e 61 67 65 6d 65 6e 74 2f 53 79 73 74 65 6d 53 65 74 2f 48 6f 75 73 65 53 65 74 2f 42 61 74 63 68 55 70 64 61 74 65 } //CrmManagement/MemberManagement/SystemSet/HouseSet/BatchUpdate  00 00 
	condition:
		any of ($a_*)
 
}