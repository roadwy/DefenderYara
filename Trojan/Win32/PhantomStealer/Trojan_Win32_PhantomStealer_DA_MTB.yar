
rule Trojan_Win32_PhantomStealer_DA_MTB{
	meta:
		description = "Trojan:Win32/PhantomStealer.DA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-50] 24 00 } //10
		$a_00_1 = {24 00 65 00 6e 00 76 00 3a 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 2b 00 } //1 $env:appdata+
		$a_00_2 = {2d 00 6a 00 6f 00 69 00 6e 00 20 00 27 00 27 00 3b 00 2e 00 28 00 24 00 } //1 -join '';.($
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=12
 
}