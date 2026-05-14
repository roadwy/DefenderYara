
rule Trojan_Win64_Vidar_B_AMTB{
	meta:
		description = "Trojan:Win64/Vidar.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 20 47 72 61 62 62 65 72 20 52 75 6c 65 73 } //1 File Grabber Rules
		$a_81_1 = {50 61 73 73 77 6f 72 64 } //1 Password
		$a_81_2 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_3 = {42 72 6f 77 73 65 72 20 4c 69 73 74 } //1 Browser List
		$a_81_4 = {57 61 6c 6c 65 74 20 52 75 6c 65 73 } //1 Wallet Rules
		$a_81_5 = {44 45 41 44 42 45 45 46 } //1 DEADBEEF
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}