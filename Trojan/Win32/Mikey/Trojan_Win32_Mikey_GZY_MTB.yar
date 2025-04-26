
rule Trojan_Win32_Mikey_GZY_MTB{
	meta:
		description = "Trojan:Win32/Mikey.GZY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 07 8b d0 c1 c2 0f 8b f0 c1 c6 0d 33 d6 c1 e8 0a 33 d0 8b c1 c1 c0 0e 8b f1 c1 ce 07 33 c6 c1 e9 03 33 c1 03 d0 03 57 c8 03 57 ec 89 57 08 01 6c 24 14 66 8b 4c 24 14 8b 44 24 18 0f bf d1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}