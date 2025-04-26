
rule Trojan_Win32_Cobaltstrike_HE_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.HE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 c6 7e 17 48 89 c2 83 e2 07 41 8a 14 16 41 32 54 05 00 88 14 03 48 ff c0 eb e5 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}