
rule Trojan_Win32_Cobaltstrike_EK_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 02 8b 45 c4 03 45 a4 03 45 9c 2b 45 9c 89 45 a0 8b 45 d8 8b 00 8b 55 a0 03 55 9c 2b 55 9c 33 c2 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}