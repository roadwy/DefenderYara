
rule Trojan_Win32_MpTamperBCD_A{
	meta:
		description = "Trojan:Win32/MpTamperBCD.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 [0-08] 73 00 65 00 74 00 } //2
		$a_00_1 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 65 00 6c 00 61 00 6d 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 20 00 74 00 72 00 75 00 65 00 } //1 disableelamdrivers true
		$a_00_2 = {64 00 69 00 73 00 61 00 62 00 6c 00 65 00 65 00 6c 00 61 00 6d 00 64 00 72 00 69 00 76 00 65 00 72 00 73 00 20 00 31 00 } //1 disableelamdrivers 1
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}