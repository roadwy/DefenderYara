
rule Trojan_Win32_DllInject_GBQ_MTB{
	meta:
		description = "Trojan:Win32/DllInject.GBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 31 4e 65 6f } //02 00  One1Neo
		$a_01_1 = {54 77 6f 32 4e 65 6f } //02 00  Two2Neo
		$a_01_2 = {54 68 72 33 4e 65 6f } //02 00  Thr3Neo
		$a_01_3 = {4f 6e 65 38 4e 65 6f } //02 00  One8Neo
		$a_01_4 = {54 77 6f 38 4e 65 6f } //02 00  Two8Neo
		$a_01_5 = {54 68 72 38 4e 65 6f } //02 00  Thr8Neo
		$a_01_6 = {72 74 68 72 79 6a 74 2e 64 6c 6c } //02 00  rthryjt.dll
		$a_01_7 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //00 00  WaitForSingleObject
	condition:
		any of ($a_*)
 
}