
rule Trojan_Win32_CobaltStrike_UNK_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.UNK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 88 cc 00 00 00 8b 90 2c 01 00 00 8b 88 80 00 00 00 31 0c 32 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}