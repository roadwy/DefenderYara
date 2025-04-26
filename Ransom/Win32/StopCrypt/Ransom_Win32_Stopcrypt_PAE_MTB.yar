
rule Ransom_Win32_Stopcrypt_PAE_MTB{
	meta:
		description = "Ransom:Win32/Stopcrypt.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 31 4d fc 8b 45 fc 01 05 ?? ?? ?? ?? 2b 75 fc 83 0d ?? ?? ?? ?? ff 8b ce c1 e1 ?? 03 4d e8 8b c6 c1 e8 ?? 03 45 e0 8d 14 33 33 ca 33 c8 2b f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}