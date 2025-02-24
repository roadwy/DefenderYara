
rule Trojan_Win32_Zusy_AMCY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf 39 4c 24 ?? 76 19 83 7c 24 ?? 0f 8d 44 24 ?? 0f 47 44 24 ?? 80 34 08 52 41 3b 4c 24 ?? 72 ?? 8d 54 24 ?? 8d 4c 24 ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}