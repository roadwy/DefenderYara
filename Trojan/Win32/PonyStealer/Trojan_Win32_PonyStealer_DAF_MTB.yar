
rule Trojan_Win32_PonyStealer_DAF_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.DAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 0f 64 c1 66 0f e8 d5 0f 73 f7 36 66 0f d5 f4 66 0f ef c4 66 0f 76 d7 66 0f fd d6 66 0f d8 c4 66 0f e9 c2 66 0f 64 e8 66 0f 67 c4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}