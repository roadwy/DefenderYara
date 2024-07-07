
rule Backdoor_Win32_NetWiredRC_D{
	meta:
		description = "Backdoor:Win32/NetWiredRC.D,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 36 77 28 28 37 37 37 36 35 7a 3b 31 2b 39 37 90 02 ff 5a 58 50 45 57 58 5a 58 50 45 57 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}