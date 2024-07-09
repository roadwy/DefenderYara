
rule Trojan_BAT_Netwire_IRJ_MTB{
	meta:
		description = "Trojan:BAT/Netwire.IRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 d6 12 00 06 0b 07 03 16 28 ?? ?? ?? 0a 6f ?? ?? ?? 06 28 ?? ?? ?? 0a 14 72 9a c8 00 70 72 a6 c8 00 70 72 aa c8 00 70 28 ?? ?? ?? 0a 72 b2 c8 00 70 72 b8 c8 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 18 8d 17 00 00 01 25 17 18 8d 17 00 00 01 25 16 05 a2 25 17 04 a2 a2 14 14 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 2b 00 06 2a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}