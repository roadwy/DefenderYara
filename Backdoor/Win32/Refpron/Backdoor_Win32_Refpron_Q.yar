
rule Backdoor_Win32_Refpron_Q{
	meta:
		description = "Backdoor:Win32/Refpron.Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_10_0 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 62 65 6d } //1 software\microsoft\wbem
		$a_00_1 = {65 5f 72 5f 72 5f 6f 5f 72 5f 00 } //1
		$a_00_2 = {7c 6a 73 61 63 74 69 76 69 74 79 2e 63 6f 6d } //1 |jsactivity.com
		$a_00_3 = {62 66 6b 71 2e 63 6f 6d 7c } //1 bfkq.com|
	condition:
		((#a_10_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}