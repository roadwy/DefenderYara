
rule Trojan_Win64_Lazy_AB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 a8 e2 76 09 00 46 04 15 1f e4 10 b4 dd 01 82 3a 52 eb 20 14 ef d8 be 2c 0e 8d 42 5c 0f a0 dc fa 80 c9 4f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Lazy_AB_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {46 41 54 41 4c 3a 20 50 61 79 6c 6f 61 64 20 6e 6f 74 20 66 6f 75 6e 64 20 61 6e 79 77 68 65 72 65 21 } //1 FATAL: Payload not found anywhere!
		$a_81_1 = {53 54 41 47 45 20 35 3a 20 44 65 63 72 79 70 74 20 50 61 79 6c 6f 61 64 } //1 STAGE 5: Decrypt Payload
		$a_81_2 = {46 41 54 41 4c 3a 20 41 6e 61 6c 79 73 69 73 20 65 6e 76 69 72 6f 6e 6d 65 6e 74 20 64 65 74 65 63 74 65 64 21 20 43 6f 6e 66 69 64 65 6e 63 65 3a 20 25 75 25 25 } //1 FATAL: Analysis environment detected! Confidence: %u%%
		$a_81_3 = {5b 4d 4f 4e 49 54 4f 52 5d 20 2d 2d 2d 20 50 72 6f 63 65 73 73 20 49 6e 6a 65 63 74 69 6f 6e 20 2d 2d 2d } //1 [MONITOR] --- Process Injection ---
		$a_81_4 = {49 6e 64 69 72 65 63 74 20 73 79 73 63 61 6c 6c 73 20 69 6e 69 74 69 61 6c 69 7a 65 64 20 28 45 54 57 2f 41 4d 53 49 2f 68 6f 6f 6b 73 20 62 79 70 61 73 73 65 64 29 } //1 Indirect syscalls initialized (ETW/AMSI/hooks bypassed)
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}