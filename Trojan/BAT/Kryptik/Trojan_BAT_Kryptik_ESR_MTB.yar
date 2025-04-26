
rule Trojan_BAT_Kryptik_ESR_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.ESR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d0 5a 00 00 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 03 6f ?? ?? ?? 0a 17 8d 17 00 00 01 25 16 d0 01 00 00 1b 28 ?? ?? ?? 0a a2 28 ?? ?? ?? 0a 04 17 8d 10 00 00 01 25 16 02 a2 6f ?? ?? ?? 0a 0a 2b 00 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}