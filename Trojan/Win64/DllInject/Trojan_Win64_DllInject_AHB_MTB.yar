
rule Trojan_Win64_DllInject_AHB_MTB{
	meta:
		description = "Trojan:Win64/DllInject.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 69 6e 75 69 6e 67 20 77 69 74 68 20 73 74 61 72 74 75 70 20 6c 6f 67 69 63 2e 2e 2e } //10 Continuing with startup logic...
		$a_01_1 = {41 6d 61 6c 67 61 6d 4c 6f 61 64 65 72 } //20 AmalgamLoader
		$a_01_2 = {41 75 74 6f 2d 69 6e 6a 65 63 74 6f 72 20 69 6e 69 74 69 61 6c 69 7a 65 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //30 Auto-injector initialized successfully
		$a_01_3 = {49 6e 69 74 69 61 6c 69 7a 69 6e 67 20 73 65 63 75 72 69 74 79 20 73 75 62 73 79 73 74 65 6d 20 66 6f 72 20 61 6e 74 69 2d 73 61 6e 64 62 6f 78 20 61 6e 64 20 65 76 61 73 69 6f 6e 2e 2e 2e } //40 Initializing security subsystem for anti-sandbox and evasion...
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}