
rule Trojan_Win32_Agent_HG{
	meta:
		description = "Trojan:Win32/Agent.HG,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {73 70 79 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } //02 00 
		$a_01_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 61 00 73 00 64 00 66 00 77 00 65 00 65 00 } //01 00  Global\asdfwee
		$a_01_2 = {72 62 2b 00 57 00 69 00 6e 00 53 00 74 00 61 00 30 } //02 00 
		$a_01_3 = {73 76 63 68 6f 73 74 2e 64 6c 6c } //02 00  svchost.dll
		$a_01_4 = {2f 76 69 70 2f 31 33 31 32 2f 69 70 2e 74 78 74 } //00 00  /vip/1312/ip.txt
	condition:
		any of ($a_*)
 
}