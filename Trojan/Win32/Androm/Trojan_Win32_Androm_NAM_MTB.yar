
rule Trojan_Win32_Androm_NAM_MTB{
	meta:
		description = "Trojan:Win32/Androm.NAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 3a 8b 8d 90 01 04 2b cb 03 4d 10 33 c0 40 3b c8 0f 86 a5 01 00 00 6a 02 8d 85 44 e5 ff ff 53 50 e8 48 aa 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}