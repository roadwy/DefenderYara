
rule Trojan_Win32_DataStealer_VD_MTB{
	meta:
		description = "Trojan:Win32/DataStealer.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 83 e0 90 02 40 8a 45 90 01 01 34 90 01 01 88 45 90 01 01 03 11 90 13 8a 45 90 01 01 88 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}