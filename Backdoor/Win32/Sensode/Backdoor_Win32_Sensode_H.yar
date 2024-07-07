
rule Backdoor_Win32_Sensode_H{
	meta:
		description = "Backdoor:Win32/Sensode.H,SIGNATURE_TYPE_PEHSTR,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_01_0 = {5a 58 53 68 65 6c 6c } //5 ZXShell
		$a_01_1 = {55 70 74 69 6d 65 3a 20 25 2d 2e 32 64 20 44 61 79 73 20 25 2d 2e 32 64 20 48 6f 75 72 73 20 25 2d 2e 32 64 20 4d 69 6e 75 74 65 73 20 25 2d 2e 32 64 20 53 65 63 6f 6e 64 73 } //5 Uptime: %-.2d Days %-.2d Hours %-.2d Minutes %-.2d Seconds
		$a_01_2 = {53 68 65 6c 6c 20 73 65 74 75 70 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 3a } //5 Shell setup information:
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}