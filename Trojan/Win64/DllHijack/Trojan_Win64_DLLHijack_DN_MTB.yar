
rule Trojan_Win64_DLLHijack_DN_MTB{
	meta:
		description = "Trojan:Win64/DLLHijack.DN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 52 01 48 8b cb 49 0f 45 c9 41 ff c0 0f b6 44 0c [0-01] 4c 8d 49 01 30 42 ff 49 63 c0 48 3b c7 90 09 04 00 49 83 f9 } //10
		$a_03_1 = {33 c9 48 8d 52 01 49 83 f9 15 49 0f 45 c9 41 ff c0 0f b6 44 0c [0-01] 4c 8d 49 01 30 42 ff 49 63 c0 48 3b c3 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}