
rule Trojan_Win32_DarkGate_GVA_MTB{
	meta:
		description = "Trojan:Win32/DarkGate.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 0d 00 ff ff ff 40 8b 4d 08 0f b6 14 01 8b 45 0c 03 45 fc 0f b6 08 33 ca 8b 55 0c 03 55 fc 88 0a } //3
		$a_01_1 = {40 8b 4d 08 88 81 00 01 00 00 8b 55 08 0f b6 82 01 01 00 00 8b 4d 08 0f b6 91 00 01 00 00 8b 4d 08 0f b6 14 11 03 c2 25 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}