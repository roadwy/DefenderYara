
rule Trojan_Win32_Tedy_AB_MTB{
	meta:
		description = "Trojan:Win32/Tedy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 a9 00 80 0f 95 c0 8b 15 c0 97 6b 00 8b 12 32 82 d4 00 00 00 0f 84 fa 00 00 00 a1 14 f6 6b 00 8b 10 ff 52 08 a1 10 f6 6b 00 8b 58 08 4b 85 db 0f 8c ae 00 00 00 43 33 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}