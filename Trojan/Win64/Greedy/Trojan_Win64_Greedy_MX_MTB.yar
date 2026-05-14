
rule Trojan_Win64_Greedy_MX_MTB{
	meta:
		description = "Trojan:Win64/Greedy.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 32 f6 48 8b 4c 24 68 48 85 c9 74 41 48 8b 54 24 78 48 2b d1 48 8b c1 } //1
		$a_01_1 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 43 6f 6d 6d 61 6e 64 20 43 6f 6d 70 72 65 73 73 2d 41 72 63 68 69 76 65 20 2d 50 61 74 68 } //1 powershell.exe -Command Compress-Archive -Path
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}