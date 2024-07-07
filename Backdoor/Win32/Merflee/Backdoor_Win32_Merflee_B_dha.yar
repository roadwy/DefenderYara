
rule Backdoor_Win32_Merflee_B_dha{
	meta:
		description = "Backdoor:Win32/Merflee.B!dha,SIGNATURE_TYPE_PEHSTR,ffffffe8 03 ffffffe8 03 03 00 00 "
		
	strings :
		$a_01_0 = {64 41 6e 64 49 46 65 65 6c 46 69 6e 65 52 45 4d } //1 dAndIFeelFineREM
		$a_01_1 = {42 53 32 50 72 6f 78 79 20 45 72 72 6f 72 3a 20 52 65 71 75 65 73 74 65 64 20 68 6f 73 74 20 69 73 20 6e 6f 74 20 61 76 61 69 6c 61 62 6c 65 2e 20 50 6c 65 61 73 65 20 74 72 79 20 61 67 61 69 6e 20 6c 61 74 65 72 2e 2e } //1 BS2Proxy Error: Requested host is not available. Please try again later..
		$a_01_2 = {61 62 65 32 38 36 39 66 2d 39 62 34 37 2d 34 63 64 39 2d 61 33 35 38 2d 63 32 32 39 30 34 64 62 61 37 66 37 } //1 abe2869f-9b47-4cd9-a358-c22904dba7f7
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1000
 
}