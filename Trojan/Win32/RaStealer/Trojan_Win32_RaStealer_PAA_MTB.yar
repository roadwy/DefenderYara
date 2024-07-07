
rule Trojan_Win32_RaStealer_PAA_MTB{
	meta:
		description = "Trojan:Win32/RaStealer.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 05 c7 05 90 01 08 89 45 0c 8b 45 f4 01 45 0c 8b c6 c1 e0 04 03 45 f0 8d 0c 33 33 c1 33 45 0c 81 c3 90 01 04 2b f8 ff 4d 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}