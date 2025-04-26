
rule Trojan_Win32_Foreign_DW_MTB{
	meta:
		description = "Trojan:Win32/Foreign.DW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 08 c1 e9 08 33 d1 8b 45 08 8b 08 03 ca 03 4d 10 8b 55 0c 8b 02 2b c1 8b 4d 0c 89 01 8b 55 08 8b 45 0c 8b 08 89 0a 83 7d fc 14 75 02 eb 02 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}