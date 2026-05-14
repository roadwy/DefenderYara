
rule Trojan_Win64_Lazy_GVM_MTB{
	meta:
		description = "Trojan:Win64/Lazy.GVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {31 34 34 2e 31 32 34 2e 32 34 32 2e 37 30 } //2 144.124.242.70
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 SOFTWARE\Microsoft\Windows NT\CurrentVersion
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}