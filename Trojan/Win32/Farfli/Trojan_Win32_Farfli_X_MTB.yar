
rule Trojan_Win32_Farfli_X_MTB{
	meta:
		description = "Trojan:Win32/Farfli.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {99 f7 f9 8b 45 90 01 01 8b 3d 90 01 04 8b ca 33 d2 33 c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}