
rule Trojan_Win32_DllInject_MK_MTB{
	meta:
		description = "Trojan:Win32/DllInject.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 50 72 6f } //03 00 
		$a_01_1 = {54 77 6f 50 72 6f } //03 00 
		$a_01_2 = {54 68 72 50 72 6f } //01 00 
		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}