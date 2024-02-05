
rule Trojan_Win32_Azorult_NO_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 81 ec 90 02 04 a1 90 02 04 33 90 01 01 89 45 fc 56 33 f6 85 ff 7e 3d 8d 90 02 05 e8 90 02 04 30 90 02 02 83 90 02 02 90 18 46 3b f7 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}