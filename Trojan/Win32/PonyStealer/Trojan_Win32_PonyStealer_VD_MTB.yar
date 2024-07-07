
rule Trojan_Win32_PonyStealer_VD_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f5 85 d2 90 02 40 8a 03 34 90 01 01 8b d6 03 d1 90 13 88 02 90 00 } //1
		$a_03_1 = {f7 f1 85 d2 90 02 40 8b 45 90 01 01 8a 80 90 01 04 34 90 01 01 8b 55 90 01 01 03 55 90 01 01 88 02 90 02 40 8b 45 90 01 01 8a 80 90 01 04 8b 55 90 01 01 03 55 90 01 01 88 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}