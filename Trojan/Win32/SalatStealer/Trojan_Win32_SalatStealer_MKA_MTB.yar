
rule Trojan_Win32_SalatStealer_MKA_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 28 ca 0f 57 c8 0f 11 49 ?? 0f 28 ca 0f 10 41 ?? 0f 57 c2 0f 11 41 ?? 0f 10 41 ?? 0f 57 c2 0f 11 41 ?? 0f 10 41 ?? 0f 57 c8 0f 11 49 ?? 3b 85 dc fc ff ff } //35
	condition:
		((#a_03_0  & 1)*35) >=35
 
}