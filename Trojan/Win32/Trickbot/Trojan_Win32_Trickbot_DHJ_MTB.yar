
rule Trojan_Win32_Trickbot_DHJ_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.DHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {43 72 79 70 74 45 6e 63 72 79 70 74 [0-06] 43 72 79 70 74 49 6d 70 6f 72 74 4b 65 79 [0-06] 43 72 79 70 74 41 63 71 75 69 72 65 43 6f 6e 74 65 78 74 57 } //1
		$a_03_1 = {52 65 73 6f 75 72 63 65 [0-0a] 52 65 73 6f 75 72 63 65 [0-06] 4c 6f 61 64 52 65 73 6f 75 72 63 65 [0-06] 46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //1
		$a_81_2 = {61 6d 75 4e 78 45 63 6f 6c 6c 41 6c 61 75 74 72 69 56 } //1 amuNxEcollAlautriV
		$a_81_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 4e 75 6d 61 } //1 VirtualAllocExNuma
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=3
 
}