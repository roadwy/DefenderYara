
rule Trojan_Win64_DllInject_CXIV_MTB{
	meta:
		description = "Trojan:Win64/DllInject.CXIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6e 69 74 72 6f 6e 65 74 5c 6e 69 74 72 6f 67 65 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 20 2d 20 6d 73 69 2e 64 6c 6c 5c 4e 69 74 72 6f 67 65 6e 2e 70 64 62 } //01 00  \nitronet\nitrogen\x64\Release - msi.dll\Nitrogen.pdb
		$a_01_1 = {54 00 69 00 6d 00 65 00 20 00 54 00 72 00 69 00 67 00 67 00 65 00 72 00 } //01 00  Time Trigger
		$a_01_2 = {49 00 64 00 6c 00 65 00 20 00 54 00 72 00 69 00 67 00 67 00 65 00 72 00 } //01 00  Idle Trigger
		$a_01_3 = {44 00 61 00 69 00 6c 00 79 00 20 00 54 00 72 00 69 00 67 00 67 00 65 00 72 00 } //01 00  Daily Trigger
		$a_01_4 = {41 56 4e 69 74 72 6f 67 65 6e 54 61 72 67 65 74 40 40 } //00 00  AVNitrogenTarget@@
	condition:
		any of ($a_*)
 
}