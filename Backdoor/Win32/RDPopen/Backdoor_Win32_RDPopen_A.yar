
rule Backdoor_Win32_RDPopen_A{
	meta:
		description = "Backdoor:Win32/RDPopen.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 e8 54 99 b9 1a 00 00 00 f7 f9 83 c2 61 8b 45 08 88 10 eb 2f } //01 00 
		$a_01_1 = {8b 55 08 0f be 02 85 c0 74 0f 8b 4d 08 8a 11 80 ea 01 8b 45 08 88 10 eb de } //00 00 
	condition:
		any of ($a_*)
 
}