
rule Ransom_Win32_LockFile_MK_MTB{
	meta:
		description = "Ransom:Win32/LockFile.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {45 6e 63 6f 64 69 6e 67 50 61 72 61 6d 65 74 65 72 73 } //EncodingParameters  01 00 
		$a_80_1 = {4c 4f 43 4b 46 49 4c 45 } //LOCKFILE  01 00 
		$a_80_2 = {3c 63 6f 6d 70 75 74 65 72 6e 61 6d 65 3e 25 73 3c 2f 63 6f 6d 70 75 74 65 72 6e 61 6d 65 3e } //<computername>%s</computername>  01 00 
		$a_80_3 = {3c 62 6c 6f 63 6b 6e 75 6d 3e 25 64 3c 2f 62 6c 6f 63 6b 6e 75 6d 3e } //<blocknum>%d</blocknum>  01 00 
		$a_80_4 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 } //winsta0\default  01 00 
		$a_80_5 = {63 6d 64 2e 65 78 65 } //cmd.exe  00 00 
	condition:
		any of ($a_*)
 
}