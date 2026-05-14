
rule Trojan_Win64_Mint_AHC_MTB{
	meta:
		description = "Trojan:Win64/Mint.AHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {41 31 ef 41 c1 c7 ?? 43 8d 2c bf 81 c5 ?? ?? ?? ?? 45 0f b6 3c 1e 48 83 c3 ?? 45 84 ff 75 } //30
		$a_01_1 = {44 61 74 61 20 74 72 61 6e 73 66 65 72 20 63 6f 6d 70 6c 65 74 65 2e 20 5b } //20 Data transfer complete. [
		$a_01_2 = {45 78 65 63 75 74 69 6e 67 20 73 63 68 65 64 75 6c 65 64 20 74 61 73 6b 73 2e 2e 2e } //10 Executing scheduled tasks...
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}