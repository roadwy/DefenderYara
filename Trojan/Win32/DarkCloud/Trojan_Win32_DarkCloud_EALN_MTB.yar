
rule Trojan_Win32_DarkCloud_EALN_MTB{
	meta:
		description = "Trojan:Win32/DarkCloud.EALN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 48 0c 8b 85 28 ff ff ff 8b b5 20 ff ff ff 8a 14 02 32 14 31 8b 45 cc 8b 48 0c 8b 85 18 ff ff ff 88 14 01 c7 45 fc 0b 00 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}