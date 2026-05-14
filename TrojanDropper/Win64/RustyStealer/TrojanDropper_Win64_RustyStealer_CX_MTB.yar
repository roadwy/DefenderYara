
rule TrojanDropper_Win64_RustyStealer_CX_MTB{
	meta:
		description = "TrojanDropper:Win64/RustyStealer.CX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 0b 00 00 "
		
	strings :
		$a_01_0 = {5c 61 70 70 5f 73 68 65 6c 6c 2e 72 73 } //5 \app_shell.rs
		$a_01_1 = {5c 68 61 6c 6f 5f 67 61 74 65 2e 72 73 } //5 \halo_gate.rs
		$a_01_2 = {5c 76 63 72 75 6e 74 69 6d 65 31 34 30 2e 64 6c 6c } //5 \vcruntime140.dll
		$a_01_3 = {75 73 65 72 33 32 2e 64 6c 6c 73 68 65 6c 6c 33 32 2e 64 6c 6c } //5 user32.dllshell32.dll
		$a_01_4 = {63 6d 64 2e 65 78 65 20 70 69 6e 67 20 2d 6e 20 33 20 31 32 37 2e 30 2e 30 2e 31 20 3e 6e 75 6c 20 26 20 64 65 6c } //5 cmd.exe ping -n 3 127.0.0.1 >nul & del
		$a_01_5 = {42 4c 4f 43 4b 45 44 20 62 79 20 61 6e 74 69 2d 76 6d } //5 BLOCKED by anti-vm
		$a_01_6 = {73 74 65 67 6f 20 64 65 63 6f 64 65 64 3a } //5 stego decoded:
		$a_01_7 = {64 65 63 72 79 70 74 65 64 20 70 65 3a } //5 decrypted pe:
		$a_01_8 = {73 6c 65 65 70 69 6e 67 20 62 65 66 6f 72 65 20 47 68 6f 73 74 } //5 sleeping before Ghost
		$a_01_9 = {47 68 6f 73 74 20 66 61 6c 6c 62 61 63 6b } //5 Ghost fallback
		$a_01_10 = {73 61 6e 64 62 6f 78 } //5 sandbox
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5+(#a_01_7  & 1)*5+(#a_01_8  & 1)*5+(#a_01_9  & 1)*5+(#a_01_10  & 1)*5) >=20
 
}