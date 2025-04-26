
rule Trojan_Win32_Ragzil_C{
	meta:
		description = "Trojan:Win32/Ragzil.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 61 6e 74 69 76 6d 2e 72 73 } //3 \antivm.rs
		$a_01_1 = {5c 72 75 6e 70 65 2e 72 73 } //3 \runpe.rs
		$a_01_2 = {5c 63 6f 6e 66 69 67 2e 72 73 } //1 \config.rs
		$a_01_3 = {5c 63 72 79 70 74 6f 2e 72 73 } //1 \crypto.rs
		$a_01_4 = {5c 75 74 69 6c 73 2e 72 73 } //1 \utils.rs
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}