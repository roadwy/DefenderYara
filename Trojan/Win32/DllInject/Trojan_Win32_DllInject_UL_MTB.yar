
rule Trojan_Win32_DllInject_UL_MTB{
	meta:
		description = "Trojan:Win32/DllInject.UL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a d9 2a da 80 e3 ed 32 19 32 d8 88 19 03 4d f8 3b ce } //00 00 
	condition:
		any of ($a_*)
 
}