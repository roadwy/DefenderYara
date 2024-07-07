
rule Trojan_Win64_TerraCrypt_AC_MTB{
	meta:
		description = "Trojan:Win64/TerraCrypt.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 08 48 31 c0 48 89 c0 50 48 c7 c0 00 00 00 08 48 89 c0 50 48 c7 c0 40 00 00 00 48 89 c0 50 48 8d 44 24 78 48 89 c0 50 48 31 c0 48 89 c0 50 48 c7 c0 0e 00 00 00 48 89 c0 50 48 8d 84 24 98 00 00 00 48 89 c0 50 59 5a 41 58 41 59 48 83 ec 20 e8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}