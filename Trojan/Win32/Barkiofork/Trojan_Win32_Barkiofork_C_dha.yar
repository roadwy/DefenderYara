
rule Trojan_Win32_Barkiofork_C_dha{
	meta:
		description = "Trojan:Win32/Barkiofork.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 67 63 75 72 74 61 69 6e 2e 63 6f 6d } //1 hgcurtain.com
		$a_01_1 = {26 70 3d 31 26 65 3d 32 26 73 65 65 64 3d } //1 &p=1&e=2&seed=
		$a_01_2 = {2f 73 2f 61 73 70 3f 74 72 3d } //1 /s/asp?tr=
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}