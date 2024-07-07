
rule Backdoor_Win32_BianDoor_C{
	meta:
		description = "Backdoor:Win32/BianDoor.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 61 2e 6f 75 74 2e 65 78 65 00 45 6e 74 72 79 00 5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 90 01 01 6f 72 74 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}