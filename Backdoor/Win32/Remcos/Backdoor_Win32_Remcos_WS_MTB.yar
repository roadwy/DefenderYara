
rule Backdoor_Win32_Remcos_WS_MTB{
	meta:
		description = "Backdoor:Win32/Remcos.WS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {66 69 6c 65 90 01 03 69 6e 90 01 05 00 00 00 66 90 01 01 63 c1 a9 90 01 04 a9 90 01 04 66 0f 6a d2 a9 90 01 04 a9 90 01 04 0f 63 f7 a9 90 01 04 31 1c 08 a9 90 01 04 a9 90 01 04 66 0f 68 ef a9 90 01 04 a9 90 01 04 a9 90 01 04 66 0f 6b f5 a9 90 01 04 a9 90 01 04 66 0f 69 c5 a9 90 01 04 a9 90 01 04 66 0f 6b f7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}