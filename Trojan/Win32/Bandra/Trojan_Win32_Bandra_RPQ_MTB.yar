
rule Trojan_Win32_Bandra_RPQ_MTB{
	meta:
		description = "Trojan:Win32/Bandra.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 c1 99 f7 7d f0 0f b6 84 15 e8 fe ff ff 8b 4d 10 03 4d ec 0f b6 09 33 c8 8b 45 10 03 45 ec 88 08 8b 45 ec 40 89 45 ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}