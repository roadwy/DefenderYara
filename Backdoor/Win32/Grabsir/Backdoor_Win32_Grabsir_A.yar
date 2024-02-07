
rule Backdoor_Win32_Grabsir_A{
	meta:
		description = "Backdoor:Win32/Grabsir.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 03 00 "
		
	strings :
		$a_01_0 = {53 00 54 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 20 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 69 00 6e 00 67 00 } //02 00  ST Service Scheduling
		$a_01_1 = {25 00 73 00 5c 00 6e 00 65 00 77 00 67 00 61 00 74 00 65 00 2e 00 74 00 78 00 74 00 } //02 00  %s\newgate.txt
		$a_01_2 = {26 25 73 64 61 25 73 74 61 3d 25 64 25 73 25 64 } //01 00  &%sda%sta=%d%s%d
		$a_01_3 = {61 62 65 32 38 36 39 66 2d 39 62 34 37 2d 34 63 64 39 2d 61 33 35 38 2d 63 32 32 39 30 34 64 62 61 37 66 37 } //00 00  abe2869f-9b47-4cd9-a358-c22904dba7f7
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}