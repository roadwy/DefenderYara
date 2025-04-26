
rule Trojan_Win32_JakyllHyde_DEA_MTB{
	meta:
		description = "Trojan:Win32/JakyllHyde.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_81_0 = {2f 2f 65 33 65 37 65 37 31 61 30 62 32 38 62 35 65 39 36 63 63 34 39 32 65 36 33 36 37 32 32 66 37 33 2f 2f 34 73 56 4b 41 4f 76 75 33 44 2f 2f 42 44 59 6f 74 30 4e 78 79 47 2e 70 68 70 } //1 //e3e7e71a0b28b5e96cc492e636722f73//4sVKAOvu3D//BDYot0NxyG.php
		$a_81_1 = {61 73 73 73 73 7a 7a 6a 64 64 64 64 64 64 6a 6a 6a 7a 7a 78 63 63 73 73 64 61 } //1 asssszzjddddddjjjzzxccssda
		$a_81_2 = {61 6c 74 65 72 65 64 2e 74 77 69 6c 69 67 68 74 70 61 72 61 64 6f 78 2e 63 6f 6d } //1 altered.twilightparadox.com
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=2
 
}