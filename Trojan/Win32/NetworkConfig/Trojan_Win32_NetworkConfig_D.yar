
rule Trojan_Win32_NetworkConfig_D{
	meta:
		description = "Trojan:Win32/NetworkConfig.D,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6e 00 62 00 74 00 73 00 74 00 61 00 74 00 [0-10] 2d 00 73 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}