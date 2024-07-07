
rule Trojan_Win32_CobaltStrike_SS_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SS!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 bf 04 00 00 00 99 f7 ff 8b 7d 10 8a 04 17 8b 7d 08 32 04 0f 88 04 0b 41 39 f1 7c e2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}