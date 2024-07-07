
rule Trojan_Win64_Zusy_NC_MTB{
	meta:
		description = "Trojan:Win64/Zusy.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_81_0 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 43 6f 6d 6d 61 6e 64 } //5 powershell -NoProfile -ExecutionPolicy bypass -windowstyle hidden -Command
		$a_81_1 = {2d 4e 6f 50 72 6f 66 69 6c 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 62 79 70 61 73 73 20 2d 43 6f 6d 6d 61 6e 64 20 } //5 -NoProfile -windowstyle hidden -ExecutionPolicy bypass -Command 
	condition:
		((#a_81_0  & 1)*5+(#a_81_1  & 1)*5) >=10
 
}