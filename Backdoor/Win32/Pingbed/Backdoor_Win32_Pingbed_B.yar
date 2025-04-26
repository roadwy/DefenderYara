
rule Backdoor_Win32_Pingbed_B{
	meta:
		description = "Backdoor:Win32/Pingbed.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 20 25 64 20 00 4b 69 6c 6c 69 6e 67 20 70 72 6f 63 65 73 73 20 25 73 } //1
		$a_03_1 = {3c 0a 75 0a 80 7d ?? 0d 74 04 c6 01 0d 41 88 01 88 45 90 1b 00 8b 45 ?? 41 40 89 45 90 1b 02 3b 45 ?? 72 dc } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}