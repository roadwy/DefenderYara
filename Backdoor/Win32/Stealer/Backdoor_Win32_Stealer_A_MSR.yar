
rule Backdoor_Win32_Stealer_A_MSR{
	meta:
		description = "Backdoor:Win32/Stealer.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 03 00 00 "
		
	strings :
		$a_02_0 = {0f be c0 33 c1 88 84 90 0a 0a 00 0f be 90 02 08 90 02 0a 42 83 fa 90 01 01 72 90 00 } //5
		$a_00_1 = {25 00 73 00 64 00 2e 00 65 00 25 00 73 00 63 00 20 00 22 00 25 00 73 00 20 00 3e 00 20 00 25 00 73 00 20 00 32 00 3e 00 26 00 31 00 22 00 } //1 %sd.e%sc "%s > %s 2>&1"
		$a_00_2 = {52 00 65 00 71 00 75 00 65 00 73 00 74 00 2f 00 25 00 6c 00 75 00 } //1 Request/%lu
	condition:
		((#a_02_0  & 1)*5+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=6
 
}