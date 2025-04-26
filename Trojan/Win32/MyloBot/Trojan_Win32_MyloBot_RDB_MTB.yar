
rule Trojan_Win32_MyloBot_RDB_MTB{
	meta:
		description = "Trojan:Win32/MyloBot.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0e 33 ca 81 e1 ff 00 00 00 c1 ea 08 33 14 8d ?? ?? ?? ?? 46 48 75 ?? 8b c7 8b da } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}