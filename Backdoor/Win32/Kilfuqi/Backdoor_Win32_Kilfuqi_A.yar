
rule Backdoor_Win32_Kilfuqi_A{
	meta:
		description = "Backdoor:Win32/Kilfuqi.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {fe ff ff 4b 90 01 06 69 90 01 06 6c 90 01 06 6c 90 01 06 71 90 01 06 69 90 01 06 70 90 01 06 69 90 01 06 6c 90 01 06 61 90 01 06 6e 90 01 06 67 90 00 } //01 00 
		$a_03_1 = {0c ff ff ff 44 90 01 06 6c 90 01 06 6c 90 01 06 46 90 01 06 75 90 01 06 55 90 01 06 70 90 01 06 67 90 01 06 72 90 01 06 61 90 01 06 64 90 01 06 72 90 00 } //00 00 
		$a_00_2 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}