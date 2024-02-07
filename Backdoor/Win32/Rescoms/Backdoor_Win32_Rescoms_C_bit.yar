
rule Backdoor_Win32_Rescoms_C_bit{
	meta:
		description = "Backdoor:Win32/Rescoms.C!bit,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 6d 63 6f 73 5f 4d 75 74 65 78 5f 49 6e 6a } //01 00  Remcos_Mutex_Inj
		$a_01_1 = {4b 65 79 6c 6f 67 67 65 72 20 53 74 61 72 74 65 64 } //01 00  Keylogger Started
		$a_01_2 = {55 70 6c 6f 61 64 69 6e 67 20 66 69 6c 65 20 74 6f 20 43 26 43 } //00 00  Uploading file to C&C
	condition:
		any of ($a_*)
 
}