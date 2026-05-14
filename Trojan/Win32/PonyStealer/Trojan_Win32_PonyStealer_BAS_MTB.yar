
rule Trojan_Win32_PonyStealer_BAS_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.BAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 0f d8 e9 66 0f d5 d2 66 0f ec e0 68 00 85 00 00 66 0f e8 f4 66 0f 73 d7 1c 0f 72 f3 41 6a 00 66 0f e1 d8 0f 60 fd ff d0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}