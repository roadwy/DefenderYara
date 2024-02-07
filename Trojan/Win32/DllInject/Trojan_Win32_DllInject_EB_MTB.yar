
rule Trojan_Win32_DllInject_EB_MTB{
	meta:
		description = "Trojan:Win32/DllInject.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {43 6f 6d 6d 61 6e 64 4c 69 6e 65 54 6f 41 72 67 76 57 } //03 00  CommandLineToArgvW
		$a_81_1 = {2d 2d 70 72 6f 63 65 73 73 2d 6e 61 6d 65 } //03 00  --process-name
		$a_81_2 = {2d 2d 64 75 6d 70 2d 62 6c 6f 63 6b } //03 00  --dump-block
		$a_81_3 = {44 4c 4c 20 74 6f 20 69 6e 6a 65 63 74 } //03 00  DLL to inject
		$a_81_4 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 20 69 6e 6a 65 63 74 69 6f 6e } //03 00  CreateRemoteThread injection
		$a_81_5 = {51 75 65 75 65 55 73 65 72 41 50 43 20 69 6e 6a 65 63 74 69 6f 6e } //03 00  QueueUserAPC injection
		$a_81_6 = {69 6e 6a 65 63 74 20 65 72 72 6f 72 } //00 00  inject error
	condition:
		any of ($a_*)
 
}