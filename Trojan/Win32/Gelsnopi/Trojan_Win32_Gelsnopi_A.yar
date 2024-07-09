
rule Trojan_Win32_Gelsnopi_A{
	meta:
		description = "Trojan:Win32/Gelsnopi.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {99 b9 32 00 00 00 f7 f9 83 fa ?? 0f 8e af 00 00 00 6a 01 6a 05 6a 0f } //1
		$a_01_1 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 69 70 73 65 63 } //1 %s:*:Enabled:ipsec
		$a_01_2 = {26 72 76 72 3d 25 64 00 3f 72 76 72 3d 25 64 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}