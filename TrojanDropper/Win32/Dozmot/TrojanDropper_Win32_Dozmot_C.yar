
rule TrojanDropper_Win32_Dozmot_C{
	meta:
		description = "TrojanDropper:Win32/Dozmot.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {99 b9 ff 00 00 00 f7 f9 80 fa 61 7e 05 80 fa 7a 7c 0a } //02 00 
		$a_03_1 = {80 f9 41 7c 0d 80 f9 4d 7f 08 0f be c9 83 c1 90 01 01 eb 1f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}