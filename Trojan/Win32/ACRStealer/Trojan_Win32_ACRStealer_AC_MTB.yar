
rule Trojan_Win32_ACRStealer_AC_MTB{
	meta:
		description = "Trojan:Win32/ACRStealer.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 f4 83 c2 01 89 55 f4 8b 45 f4 3b 45 f0 73 12 8b 4d e8 03 4d f4 8b 55 d0 03 55 f4 8a 02 88 01 eb dd } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}