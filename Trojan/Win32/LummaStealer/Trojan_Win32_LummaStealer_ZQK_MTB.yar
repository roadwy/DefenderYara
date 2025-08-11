
rule Trojan_Win32_LummaStealer_ZQK_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.ZQK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 72 63 5c 65 78 65 63 75 74 61 62 6c 65 5f 6c 6f 61 64 65 72 2e 72 73 } //1 src\executable_loader.rs
		$a_01_1 = {6a 04 68 00 30 00 00 ff 70 50 6a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}