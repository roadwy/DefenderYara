
rule Trojan_Win32_SnakeKeylogger_AB_MTB{
	meta:
		description = "Trojan:Win32/SnakeKeylogger.AB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 a0 99 b9 03 00 00 00 f7 f9 8b 85 18 f8 ff ff 0f be 0c 10 8b 55 a0 0f b6 44 15 a4 33 c1 8b 4d a0 88 44 0d a4 eb c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}