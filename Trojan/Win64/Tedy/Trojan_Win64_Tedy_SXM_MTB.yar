
rule Trojan_Win64_Tedy_SXM_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,41 00 41 00 04 00 00 "
		
	strings :
		$a_01_0 = {5b 48 4f 4f 4b 5d 20 52 61 77 20 49 6e 74 65 72 63 65 70 74 65 64 20 44 61 74 61 3a } //30 [HOOK] Raw Intercepted Data:
		$a_01_1 = {5b 48 4f 4f 4b 5d 20 49 6e 74 65 72 63 65 70 74 65 64 20 70 6c 61 69 6e 74 65 78 74 3a } //20 [HOOK] Intercepted plaintext:
		$a_01_2 = {5b 50 41 54 43 48 5d 20 50 65 72 73 69 73 74 65 6e 74 20 73 63 61 6e 20 72 65 70 6c 61 63 65 64 20 61 74 3a } //10 [PATCH] Persistent scan replaced at:
		$a_01_3 = {48 6f 6f 6b 44 4c 4c } //5 HookDLL
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5) >=65
 
}