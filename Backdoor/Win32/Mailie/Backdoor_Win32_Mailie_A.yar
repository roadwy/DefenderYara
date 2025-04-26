
rule Backdoor_Win32_Mailie_A{
	meta:
		description = "Backdoor:Win32/Mailie.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 25 73 2f 77 65 62 6d 61 69 6c 2e 70 68 70 3f 69 64 3d 25 73 } //1 //%s/webmail.php?id=%s
		$a_01_1 = {67 30 30 67 31 65 } //1 g00g1e
		$a_01_2 = {39 6f 30 67 6c 30 } //1 9o0gl0
		$a_01_3 = {25 73 20 2f 43 20 25 73 20 3e 3e 22 25 73 22 20 32 3e 26 31 } //1 %s /C %s >>"%s" 2>&1
		$a_01_4 = {45 78 70 6c 6f 72 65 72 5c 50 68 69 73 68 69 6e 67 46 69 6c 74 65 72 } //1 Explorer\PhishingFilter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}