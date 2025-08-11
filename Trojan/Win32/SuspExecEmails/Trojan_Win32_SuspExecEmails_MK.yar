
rule Trojan_Win32_SuspExecEmails_MK{
	meta:
		description = "Trojan:Win32/SuspExecEmails.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {2a 2e 70 73 74 20 26 20 65 78 69 74 } //*.pst & exit  1
		$a_00_3 = {61 00 34 00 38 00 39 00 36 00 63 00 66 00 38 00 2d 00 61 00 34 00 66 00 61 00 2d 00 34 00 30 00 65 00 39 00 2d 00 39 00 30 00 65 00 30 00 2d 00 33 00 62 00 32 00 64 00 64 00 63 00 33 00 65 00 33 00 63 00 65 00 31 00 } //-1 a4896cf8-a4fa-40e9-90e0-3b2ddc3e3ce1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}
rule Trojan_Win32_SuspExecEmails_MK_2{
	meta:
		description = "Trojan:Win32/SuspExecEmails.MK,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_80_0 = {65 63 68 6f 20 73 62 5f } //echo sb_  1
		$a_80_1 = {20 3e 4e 55 4c } // >NUL  1
		$a_80_2 = {2a 2e 70 73 74 20 26 20 65 78 69 74 } //*.pst & exit  1
		$a_00_3 = {63 00 34 00 38 00 39 00 36 00 63 00 66 00 38 00 2d 00 61 00 34 00 66 00 61 00 2d 00 34 00 30 00 65 00 39 00 2d 00 39 00 30 00 65 00 30 00 2d 00 33 00 62 00 32 00 64 00 64 00 63 00 33 00 65 00 33 00 63 00 65 00 32 00 } //-1 c4896cf8-a4fa-40e9-90e0-3b2ddc3e3ce2
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_00_3  & 1)*-1) >=3
 
}