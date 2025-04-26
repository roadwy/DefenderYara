
rule Trojan_Win32_Fareit_POIU_MTB{
	meta:
		description = "Trojan:Win32/Fareit.POIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {4a 73 04 89 f3 89 f8 71 0a 0c 8d ff c6 f7 c2 14 3c e5 0e 0f b7 db 43 80 e8 2a 81 fa 85 00 00 00 0f 8f da ff ff ff } //1
		$a_01_1 = {bf 40 67 0e 00 0f b6 d2 80 ea 97 81 c7 bd 02 00 00 1d 4b 11 6d a4 80 c6 9a 0f af c1 8d 1f 2b f5 8b c0 81 f3 c7 61 0e 00 80 f2 dd } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}