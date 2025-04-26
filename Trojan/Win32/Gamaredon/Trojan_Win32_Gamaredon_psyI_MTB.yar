
rule Trojan_Win32_Gamaredon_psyI_MTB{
	meta:
		description = "Trojan:Win32/Gamaredon.psyI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 28 bf 01 00 00 00 8b 45 fc 0f b6 44 38 ff 8d 4d f8 ba 02 00 00 00 e8 7c b5 fb ff 8b 55 f8 8b c6 e8 c2 78 fb ff 47 4b 75 dd 33 c0 5a 59 59 64 89 10 68 90 ce 44 00 8d 45 f8 ba 02 00 00 00 e8 00 76 fb ff c3 e9 b2 6f fb ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}