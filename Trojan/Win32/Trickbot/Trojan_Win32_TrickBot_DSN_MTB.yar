
rule Trojan_Win32_TrickBot_DSN_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.DSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 f0 33 d2 b9 08 00 00 00 f7 f1 8b 45 f8 0f be 0c 10 8b 55 f0 0f b6 82 [0-04] 33 c1 8b 4d f0 88 81 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}