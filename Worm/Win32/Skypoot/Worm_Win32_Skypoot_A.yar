
rule Worm_Win32_Skypoot_A{
	meta:
		description = "Worm:Win32/Skypoot.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 53 6b 79 70 6c 65 78 00 } //1
		$a_01_1 = {5c 48 6f 6d 65 5c 43 6f 64 65 5c 53 6b 79 70 6c 65 78 } //1 \Home\Code\Skyplex
		$a_01_2 = {6b 74 68 78 62 79 65 2e 62 61 74 } //1 kthxbye.bat
		$a_01_3 = {54 5a 61 70 43 6f 6d 6d 75 6e 69 63 61 74 6f 72 } //1 TZapCommunicator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}