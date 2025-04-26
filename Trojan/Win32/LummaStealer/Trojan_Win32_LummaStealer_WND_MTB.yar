
rule Trojan_Win32_LummaStealer_WND_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.WND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 d8 04 61 32 04 19 04 1b 88 04 19 43 83 fb 13 75 ee } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}