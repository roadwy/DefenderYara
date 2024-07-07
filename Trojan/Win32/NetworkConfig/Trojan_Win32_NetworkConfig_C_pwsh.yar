
rule Trojan_Win32_NetworkConfig_C_pwsh{
	meta:
		description = "Trojan:Win32/NetworkConfig.C!pwsh,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {77 00 69 00 6e 00 33 00 32 00 5f 00 6e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 61 00 64 00 61 00 70 00 74 00 65 00 72 00 63 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 90 02 40 2d 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}