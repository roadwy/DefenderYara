
rule Trojan_Win32_Agent_RRR_MTB{
	meta:
		description = "Trojan:Win32/Agent.RRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 77 73 64 6b 6a 67 6e 68 } //1 lowsdkjgnh
		$a_01_1 = {65 6c 6b 72 6e 67 66 70 73 } //1 elkrngfps
		$a_01_2 = {73 64 6c 6f 66 69 67 68 61 70 77 39 65 38 } //1 sdlofighapw9e8
		$a_01_3 = {64 6f 66 68 69 67 61 77 30 70 39 64 66 38 67 6d 79 71 30 33 39 38 34 79 74 72 30 71 39 70 77 65 72 68 74 } //1 dofhigaw0p9df8gmyq03984ytr0q9pwerht
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}