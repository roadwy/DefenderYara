
rule Trojan_Win32_DllInject_CB_MTB{
	meta:
		description = "Trojan:Win32/DllInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 31 4e 65 6f } //03 00  One1Neo
		$a_01_1 = {54 77 6f 32 4e 65 6f } //03 00  Two2Neo
		$a_01_2 = {54 68 72 33 4e 65 6f } //03 00  Thr3Neo
		$a_01_3 = {72 74 68 72 79 6a 74 2e 64 6c 6c } //01 00  rthryjt.dll
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_DllInject_CB_MTB_2{
	meta:
		description = "Trojan:Win32/DllInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {42 6f 73 65 6a 66 67 6f 70 73 65 69 6f 70 67 65 73 72 6a } //02 00  Bosejfgopseiopgesrj
		$a_01_1 = {4e 6f 61 73 65 69 6f 66 73 65 67 6f 69 73 65 67 6a 65 73 } //02 00  Noaseiofsegoisegjes
		$a_01_2 = {4f 6d 73 64 67 6f 73 6a 41 6f 70 64 66 6a 68 69 72 6a 68 } //02 00  OmsdgosjAopdfjhirjh
		$a_01_3 = {4f 6f 70 69 61 65 6f 69 67 66 73 65 6a 67 65 73 61 } //01 00  Oopiaeoigfsejgesa
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}