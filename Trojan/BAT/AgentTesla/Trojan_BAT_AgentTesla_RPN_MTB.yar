
rule Trojan_BAT_AgentTesla_RPN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 08 06 08 06 8e 69 5d 91 02 08 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 0d 09 2d e1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RPN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {05 49 00 6e 00 00 05 76 00 6f 00 00 05 6b 00 65 00 00 09 4c 00 6f 00 61 00 64 00 00 } //1
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 } //1 NewLateBinding
		$a_01_3 = {53 79 73 74 65 6d 2e 54 68 72 65 61 64 69 6e 67 } //1 System.Threading
		$a_01_4 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_01_5 = {4c 61 74 65 47 65 74 } //1 LateGet
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //1 FromBase64CharArray
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_RPN_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 00 38 00 2e 00 31 00 39 00 33 00 2e 00 31 00 30 00 32 00 2e 00 32 00 33 00 32 00 } //1 18.193.102.232
		$a_01_1 = {38 00 37 00 34 00 30 00 39 00 33 00 34 00 30 00 31 00 30 00 32 00 33 00 2e 00 6a 00 70 00 67 00 } //1 874093401023.jpg
		$a_01_2 = {2f 00 63 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 31 00 39 00 } //1 /c timeout 19
		$a_01_3 = {4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 62 00 79 00 74 00 65 00 73 00 } //1 Malwarebytes
		$a_01_4 = {59 00 74 00 76 00 76 00 71 00 7a 00 70 00 76 00 6f 00 77 00 73 00 71 00 61 00 79 00 64 00 6f 00 6d 00 6f 00 6f 00 71 00 77 00 74 00 } //1 Ytvvqzpvowsqaydomooqwt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}