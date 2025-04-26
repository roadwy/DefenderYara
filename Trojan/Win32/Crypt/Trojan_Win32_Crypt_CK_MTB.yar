
rule Trojan_Win32_Crypt_CK_MTB{
	meta:
		description = "Trojan:Win32/Crypt.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 07 35 84 98 c6 f0 33 06 2b c3 2d 0a bc 51 4e 89 02 83 c6 04 41 8b c1 2b 45 18 0f 85 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}