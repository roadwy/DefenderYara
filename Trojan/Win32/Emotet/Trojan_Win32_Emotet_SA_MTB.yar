
rule Trojan_Win32_Emotet_SA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 04 24 8a d0 02 d0 c0 e8 07 32 d0 80 c2 37 8a ca c0 e9 04 c0 e2 04 8b 74 24 04 0a ca 80 c1 3d 88 0c 24 8a 1c 75 08 e0 02 10 8d 7e 01 0f b7 c7 32 d9 88 5c 34 20 89 44 24 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}