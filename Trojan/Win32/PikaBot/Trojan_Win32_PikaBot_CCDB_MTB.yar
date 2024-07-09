
rule Trojan_Win32_PikaBot_CCDB_MTB{
	meta:
		description = "Trojan:Win32/PikaBot.CCDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 33 d2 eb ?? 0f b6 44 10 10 33 c8 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}