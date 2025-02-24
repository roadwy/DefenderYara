
rule Trojan_Win32_Cridex_MKV_MTB{
	meta:
		description = "Trojan:Win32/Cridex.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 ca 88 4d 13 11 0d d3 86 41 00 8b 4d e8 8b 15 ?? ?? 41 00 31 15 0b 87 41 00 0f b6 55 13 33 ce 2b cf 0f af ca 34 c3 2c 4e 88 4d 13 0f b6 4d 13 03 c1 88 45 13 8a 45 13 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}