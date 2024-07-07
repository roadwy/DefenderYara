
rule HackTool_Win64_Juicypotato{
	meta:
		description = "HackTool:Win64/Juicypotato,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {4a 75 69 63 79 50 6f 74 61 74 6f 20 76 25 73 } //1 JuicyPotato v%s
		$a_01_1 = {2d 6c 20 3c 70 6f 72 74 3e 3a 20 43 4f 4d } //1 -l <port>: COM
		$a_01_2 = {50 72 69 76 20 41 64 6a 75 73 74 20 46 41 4c 53 45 } //1 Priv Adjust FALSE
		$a_01_3 = {5b 2b 5d 20 43 72 65 61 74 65 50 72 6f 63 65 73 73 57 69 74 68 54 6f 6b 65 6e 57 20 4f 4b } //1 [+] CreateProcessWithTokenW OK
		$a_01_4 = {57 61 69 74 69 6e 67 20 66 6f 72 20 61 75 74 68 2e 2e 2e } //1 Waiting for auth...
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}