
rule Trojan_Win32_Qukart_DB_MTB{
	meta:
		description = "Trojan:Win32/Qukart.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 8b 95 [0-04] 0f b6 84 15 [0-04] 8b 95 [0-04] 0f b6 94 15 [0-04] 03 c2 25 [0-04] 79 ?? 48 0d 00 ff ff ff 40 0f b6 84 05 [0-04] 33 c8 8b 55 f8 03 95 [0-04] 88 0a e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}