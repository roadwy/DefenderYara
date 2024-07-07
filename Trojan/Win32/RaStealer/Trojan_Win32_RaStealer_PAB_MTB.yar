
rule Trojan_Win32_RaStealer_PAB_MTB{
	meta:
		description = "Trojan:Win32/RaStealer.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d c8 89 45 fc 8d 45 fc e8 90 01 04 8b 45 fc 33 45 f0 89 1d 90 01 04 31 45 f8 8b 45 f8 29 45 f4 81 45 e0 90 01 04 ff 4d dc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}