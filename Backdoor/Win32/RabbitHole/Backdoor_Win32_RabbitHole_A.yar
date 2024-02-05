
rule Backdoor_Win32_RabbitHole_A{
	meta:
		description = "Backdoor:Win32/RabbitHole.A,SIGNATURE_TYPE_PEHSTR,0c 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 47 65 74 41 63 74 69 76 65 43 6f 6d 6d 61 6e 64 73 } //01 00 
		$a_01_1 = {2f 49 73 73 75 65 43 6f 6d 6d 61 6e 64 } //05 00 
		$a_01_2 = {53 74 61 72 74 4b 65 79 6c 6f 67 67 65 72 } //05 00 
		$a_01_3 = {52 61 62 62 69 74 48 6f 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}