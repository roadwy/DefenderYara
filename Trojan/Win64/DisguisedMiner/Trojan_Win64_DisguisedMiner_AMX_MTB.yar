
rule Trojan_Win64_DisguisedMiner_AMX_MTB{
	meta:
		description = "Trojan:Win64/DisguisedMiner.AMX!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4b 38 48 85 c9 74 49 48 8b 01 ff 50 10 84 c0 75 24 48 83 c3 40 48 3b df 75 e4 48 8b 4e 40 48 8b 41 18 48 8b 50 28 80 7a 23 00 } //10
		$a_01_1 = {53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 20 00 61 00 6e 00 64 00 20 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 20 00 61 00 70 00 70 00 } //1 Services and Controller app
		$a_01_2 = {6a 00 61 00 76 00 61 00 2e 00 65 00 78 00 65 00 } //1 java.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}