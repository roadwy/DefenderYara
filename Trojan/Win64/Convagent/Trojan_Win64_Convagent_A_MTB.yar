
rule Trojan_Win64_Convagent_A_MTB{
	meta:
		description = "Trojan:Win64/Convagent.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 8b ad d8 03 00 00 49 83 ef 01 73 f3 6a 01 58 48 89 85 c0 01 00 00 45 31 ff 45 31 c0 eb 29 } //1
		$a_80_1 = {43 6f 6e 76 65 72 74 5d 3a 3a 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 28 } //Convert]::FromBase64String(  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}