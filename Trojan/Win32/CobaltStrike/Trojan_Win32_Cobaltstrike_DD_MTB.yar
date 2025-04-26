
rule Trojan_Win32_Cobaltstrike_DD_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c6 83 ec 10 31 c0 39 d8 7d ?? 8b 4d 10 89 c2 83 e2 03 8a 14 11 8b 4d 08 32 14 01 88 14 06 40 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}