
rule Ransom_Win32_Royal_MP_MTB{
	meta:
		description = "Ransom:Win32/Royal.MP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 45 ff 8b 4d 08 03 4d f8 0f b6 11 33 d0 8b 45 08 03 45 f8 88 10 0f b6 4d f0 8b 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}