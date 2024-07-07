
rule Trojan_Win32_Emotet_DDB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 7d f8 8b 45 90 01 01 0f be 14 10 03 ca 8b c1 99 b9 90 01 04 f7 f9 90 00 } //1
		$a_02_1 = {55 8b ec 8b 45 90 01 01 0b 45 90 01 01 8b 4d 90 01 01 f7 d1 8b 55 90 01 01 f7 d2 0b ca 23 c1 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}