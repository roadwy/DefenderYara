
rule Trojan_Win32_DllInject_BJ_MTB{
	meta:
		description = "Trojan:Win32/DllInject.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 4e 6f 50 72 6f } //02 00  OneNoPro
		$a_01_1 = {54 77 6f 4e 6f 50 72 6f } //02 00  TwoNoPro
		$a_01_2 = {54 68 72 4e 6f 50 72 6f } //01 00  ThrNoPro
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}