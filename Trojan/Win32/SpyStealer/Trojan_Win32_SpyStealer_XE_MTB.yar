
rule Trojan_Win32_SpyStealer_XE_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.XE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 69 72 74 c7 05 90 01 04 75 61 6c 50 c7 05 90 01 04 72 6f 74 65 66 c7 05 90 01 04 63 74 c6 05 90 01 04 00 ff 15 5c 10 40 00 a3 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}