
rule Trojan_Win64_Stealga_DD_MTB{
	meta:
		description = "Trojan:Win64/Stealga.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 53 74 65 61 6c 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c } //10 \Stealer\x64\Release\
		$a_81_1 = {44 45 43 52 59 50 54 45 44 20 4b 45 59 3a } //1 DECRYPTED KEY:
		$a_81_2 = {4e 6f 74 47 6f 6f 64 53 68 69 74 } //1 NotGoodShit
		$a_81_3 = {2e 5c 70 69 70 65 5c 47 65 74 44 61 74 61 } //1 .\pipe\GetData
		$a_81_4 = {5b 2a 5d 20 4b 65 79 20 73 61 76 65 64 20 74 6f } //1 [*] Key saved to
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=14
 
}