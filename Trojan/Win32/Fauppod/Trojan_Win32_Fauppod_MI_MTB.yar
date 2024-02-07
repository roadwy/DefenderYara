
rule Trojan_Win32_Fauppod_MI_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {49 62 67 76 79 66 44 74 76 79 } //03 00  IbgvyfDtvy
		$a_01_1 = {49 62 79 75 44 74 76 75 79 62 } //03 00  IbyuDtvuyb
		$a_01_2 = {49 79 62 75 45 63 74 66 79 76 67 } //01 00  IybuEctfyvg
		$a_01_3 = {43 6c 6f 73 65 48 61 6e 64 6c 65 } //00 00  CloseHandle
	condition:
		any of ($a_*)
 
}