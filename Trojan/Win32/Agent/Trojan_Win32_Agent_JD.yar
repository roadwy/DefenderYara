
rule Trojan_Win32_Agent_JD{
	meta:
		description = "Trojan:Win32/Agent.JD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 00 6f 00 66 00 74 00 77 00 00 00 61 00 72 00 65 00 5c 78 30 30 6d 00 69 00 63 00 72 00 00 00 00 00 6b 00 6a 00 65 00 77 00 6f 00 6f 00 70 00 69 00 } //5
		$a_01_1 = {2e 00 69 00 6e 00 69 00 00 00 00 00 47 65 74 58 6f 72 43 68 65 63 6b 53 75 6d 31 36 00 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}