
rule Trojan_Win32_Qukart_ASR_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 51 50 56 57 bf 39 4a b9 09 81 c7 9e 1d 00 00 8d 45 f8 50 8d 45 fc 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 ff 75 0c ff 75 08 e8 90 01 02 00 00 89 c6 81 ef cb 52 00 00 09 f6 74 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}