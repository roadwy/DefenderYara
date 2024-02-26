
rule Trojan_Win32_Rozena_GPB_MTB{
	meta:
		description = "Trojan:Win32/Rozena.GPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {80 f1 41 88 8c 05 9c f9 ff ff 40 3d 1e 03 00 00 72 e7 } //00 00 
	condition:
		any of ($a_*)
 
}