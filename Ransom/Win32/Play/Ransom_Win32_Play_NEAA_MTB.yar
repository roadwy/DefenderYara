
rule Ransom_Win32_Play_NEAA_MTB{
	meta:
		description = "Ransom:Win32/Play.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 8d c0 fd ff ff 83 e9 01 89 8d c0 fd ff ff 83 bd c0 fd ff ff 00 0f 8e 84 01 00 00 8b 95 b4 fd ff ff 8b 42 28 8b 8d c0 fd ff ff 0f b7 14 48 83 fa 5c 0f 85 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}