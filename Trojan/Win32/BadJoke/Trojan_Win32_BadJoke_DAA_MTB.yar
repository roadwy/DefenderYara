
rule Trojan_Win32_BadJoke_DAA_MTB{
	meta:
		description = "Trojan:Win32/BadJoke.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c1 8b 45 fc c1 f8 0b 09 c8 21 d0 89 c2 89 d0 c1 e0 02 01 d0 8d 14 85 00 00 00 00 01 d0 c1 e0 02 89 c2 8b 45 fc 8d 0c 00 8b 45 10 01 c8 66 89 10 83 45 fc 01 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}