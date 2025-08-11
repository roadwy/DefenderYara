
rule Trojan_Win32_Linx_HA_MTB{
	meta:
		description = "Trojan:Win32/Linx.HA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 72 00 65 00 63 00 79 00 63 00 6c 00 65 00 64 00 [0-30] 2e 00 64 00 61 00 74 00 2c 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}