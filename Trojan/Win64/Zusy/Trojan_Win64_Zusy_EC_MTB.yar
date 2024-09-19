
rule Trojan_Win64_Zusy_EC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 d0 48 c1 e8 02 48 31 d0 48 89 c2 48 c1 ea 15 48 31 c2 48 89 d0 48 c1 e8 16 48 31 d0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Zusy_EC_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 61 6c 6c 69 6e 67 21 } //2 Balling!
		$a_01_1 = {37 39 2e 31 37 34 2e 39 32 2e 32 32 } //2 79.174.92.22
		$a_01_2 = {46 61 74 61 6c 20 65 72 72 6f 72 20 69 6e 20 68 6f 73 74 20 6e 61 6d 65 20 72 65 73 6f 6c 76 69 6e 67 } //2 Fatal error in host name resolving
		$a_01_3 = {48 89 44 24 30 48 c7 44 24 48 87 69 00 00 48 c7 44 24 40 84 03 00 00 b9 02 02 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}
rule Trojan_Win64_Zusy_EC_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {44 65 73 61 63 74 69 76 61 64 6f 20 49 6e 74 65 72 6e 65 74 21 } //1 Desactivado Internet!
		$a_81_1 = {53 74 72 65 61 6d 20 4d 6f 64 65 20 20 44 45 53 41 43 54 49 56 41 44 4f } //1 Stream Mode  DESACTIVADO
		$a_81_2 = {6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 66 69 72 65 77 61 6c 6c 20 64 65 6c 65 74 65 20 72 75 6c 65 20 6e 61 6d 65 } //1 netsh advfirewall firewall delete rule name
		$a_81_3 = {4e 4f 53 4b 49 4c 4c 20 52 41 46 41 2e 70 64 62 } //1 NOSKILL RAFA.pdb
		$a_81_4 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //1 URLDownloadToFileA
		$a_81_5 = {54 72 61 63 6b 4d 6f 75 73 65 45 76 65 6e 74 } //1 TrackMouseEvent
		$a_81_6 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 CheckRemoteDebuggerPresent
		$a_81_7 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_81_8 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
		$a_81_9 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //1 ResumeThread
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}