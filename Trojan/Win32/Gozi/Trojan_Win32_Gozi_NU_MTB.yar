
rule Trojan_Win32_Gozi_NU_MTB{
	meta:
		description = "Trojan:Win32/Gozi.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {69 c0 6d 4e c6 41 05 39 30 00 00 8b c8 c1 e9 10 81 e1 ff 7f 00 00 81 f9 20 4e 00 00 72 e2 66 0f 6e c1 0f 28 cd f3 0f e6 c0 c1 e9 1f f2 0f 58 04 cd 90 01 04 66 0f 5a c0 0f 5a c0 f2 0f 5e c8 0f 57 c0 f2 0f 5a c1 f3 0f 11 42 fc 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}