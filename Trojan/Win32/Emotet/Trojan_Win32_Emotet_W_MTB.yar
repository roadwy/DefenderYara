
rule Trojan_Win32_Emotet_W_MTB{
	meta:
		description = "Trojan:Win32/Emotet.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 4c 8a 4c 24 33 88 08 8a 4c 24 3e 8a 54 24 3f 8b 84 24 88 01 00 00 8b 74 24 2c 29 f0 89 84 24 88 01 00 00 30 ca 8b 84 24 78 01 00 00 88 10 8b 44 24 38 83 c0 25 89 44 24 6c 39 f0 0f 82 ?? ?? ff ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}