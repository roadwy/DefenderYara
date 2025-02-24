
rule Trojan_BAT_Injuke_SHLZ_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SHLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 19 8d 40 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 2a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}