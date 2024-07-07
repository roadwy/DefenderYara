
rule Trojan_Win32_Agent_S{
	meta:
		description = "Trojan:Win32/Agent.S,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {62 62 6d 65 65 6f 6d 6e 76 70 6f 70 2e 64 6c 6c 00 42 70 6f 64 6d 73 73 65 6c 69 6f 63 44 66 72 74 6f 6f } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}