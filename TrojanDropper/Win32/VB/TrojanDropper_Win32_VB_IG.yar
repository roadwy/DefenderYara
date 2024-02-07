
rule TrojanDropper_Win32_VB_IG{
	meta:
		description = "TrojanDropper:Win32/VB.IG,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {5c 00 53 00 70 00 2d 00 42 00 69 00 6e 00 64 00 65 00 72 00 5c 00 45 00 78 00 74 00 72 00 61 00 63 00 74 00 65 00 72 00 5c 00 53 00 70 00 42 00 69 00 6e 00 64 00 65 00 72 00 45 00 78 00 74 00 72 00 61 00 63 00 74 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //00 00  \Sp-Binder\Extracter\SpBinderExtracter.vbp
	condition:
		any of ($a_*)
 
}