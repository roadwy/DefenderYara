
rule Trojan_Win32_Gozi_NV_MTB{
	meta:
		description = "Trojan:Win32/Gozi.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8d 47 20 66 83 ff 61 0f b7 c8 8d 76 02 0f b7 c7 0f 43 c8 69 d2 01 01 00 00 0f b7 c1 03 d0 c1 e0 10 33 d0 0f b7 06 8b f8 } //00 00 
	condition:
		any of ($a_*)
 
}