
rule Trojan_Win32_CobaltStrike_SZ_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SZ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 71 ff 12 80 31 12 80 71 01 12 80 71 02 12 80 71 03 12 80 71 04 12 80 71 05 12 80 71 06 12 80 71 07 12 80 71 08 12 80 71 09 12 80 71 0a 12 80 71 0b 12 80 71 0c 12 80 71 0d 12 80 71 0e 12 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}