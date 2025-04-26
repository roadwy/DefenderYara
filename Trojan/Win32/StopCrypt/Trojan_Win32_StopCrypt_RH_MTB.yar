
rule Trojan_Win32_StopCrypt_RH_MTB{
	meta:
		description = "Trojan:Win32/StopCrypt.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 83 65 fc 00 8b 45 10 01 45 fc 8b 45 fc 33 45 0c 8b 4d 08 89 01 c9 c2 0c 00 } //1
		$a_01_1 = {c7 45 fc 02 00 00 00 83 45 fc 02 8b 4d fc 8b 45 0c d3 e0 8b 4d 08 89 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}