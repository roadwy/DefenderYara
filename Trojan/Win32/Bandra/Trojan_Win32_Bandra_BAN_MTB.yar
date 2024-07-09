
rule Trojan_Win32_Bandra_BAN_MTB{
	meta:
		description = "Trojan:Win32/Bandra.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 f8 8b 45 fc 33 d2 b9 18 00 00 00 f7 f1 52 8b 4d 08 e8 [0-04] 0f be 10 8b 45 f8 0f b6 08 33 ca 8b 55 f8 88 0a eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}