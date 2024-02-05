
rule Trojan_Win32_Gozi_RD_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 c9 0d 66 19 00 56 57 bf 5f f3 6e 3c 03 cf 0f b7 c1 69 c9 0d 66 19 00 99 6a 07 5e f7 fe 03 cf 0f b7 c1 } //00 00 
	condition:
		any of ($a_*)
 
}