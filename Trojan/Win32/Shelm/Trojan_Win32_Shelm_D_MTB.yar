
rule Trojan_Win32_Shelm_D_MTB{
	meta:
		description = "Trojan:Win32/Shelm.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 88 08 21 40 00 80 f1 56 88 8c 05 90 01 02 ff ff 40 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}