
rule Trojan_Win64_r77RootKit_C_MTB{
	meta:
		description = "Trojan:Win64/r77RootKit.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 24 00 37 00 37 00 63 00 6f 00 6e 00 66 00 69 00 67 00 } //2 SOFTWARE\$77config
		$a_01_1 = {52 65 66 6c 65 63 74 69 76 65 44 6c 6c 4d 61 69 6e } //2 ReflectiveDllMain
		$a_01_2 = {5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 24 00 37 00 37 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5f 00 72 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 } //2 \.\pipe\$77control_redirect
		$a_01_3 = {5c 00 2e 00 5c 00 70 00 69 00 70 00 65 00 5c 00 24 00 37 00 37 00 63 00 68 00 69 00 6c 00 64 00 70 00 72 00 6f 00 63 00 } //2 \.\pipe\$77childproc
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}