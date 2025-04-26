
rule Backdoor_Win32_Netan_A{
	meta:
		description = "Backdoor:Win32/Netan.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 73 65 72 76 69 63 65 73 2e 65 78 65 00 00 00 00 2e 72 65 6c 6f 63 00 } //1
		$a_01_1 = {3a 34 34 33 3b 36 36 2e 31 39 37 2e } //1 :443;66.197.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}