
rule Trojan_Win64_CobaltStrike_VM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.VM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {44 65 74 65 63 74 41 74 74 61 63 6b 2e 64 6c 6c } //1 DetectAttack.dll
		$a_01_1 = {3f 41 56 70 61 69 72 4e 6f 64 65 40 40 } //1 ?AVpairNode@@
		$a_01_2 = {78 36 34 5c 44 65 62 75 67 5c 44 65 74 65 63 74 41 74 74 61 63 6b 2e 70 64 62 } //1 x64\Debug\DetectAttack.pdb
		$a_01_3 = {73 65 6e 64 28 29 20 64 65 74 6f 75 72 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 send() detoured successfully
		$a_01_4 = {62 65 61 63 6f 6e 2e 64 6c 6c } //1 beacon.dll
		$a_01_5 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 } //1 powershell -nop -exec bypass -EncodedCommand
		$a_01_6 = {6d 20 61 6c 72 65 61 64 79 20 69 6e 20 53 4d 42 20 6d 6f 64 65 } //1 m already in SMB mode
		$a_01_7 = {69 73 20 61 6e 20 78 36 34 20 70 72 6f 63 65 73 73 20 28 63 61 6e 27 74 20 69 6e 6a 65 63 74 20 78 38 36 20 63 6f 6e 74 65 6e 74 29 } //1 is an x64 process (can't inject x86 content)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}