
rule Backdoor_Win32_Shark_E{
	meta:
		description = "Backdoor:Win32/Shark.E,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 00 73 00 68 00 61 00 72 00 4b 00 20 00 33 00 5c 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 \sharK 3\Injector\Project1.vbp
		$a_01_1 = {6d 6f 64 55 73 65 72 6c 61 6e 64 55 6e 68 6f 6f 6b 69 6e 67 } //1 modUserlandUnhooking
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}