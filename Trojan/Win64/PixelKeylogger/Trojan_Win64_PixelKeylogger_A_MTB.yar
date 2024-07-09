
rule Trojan_Win64_PixelKeylogger_A_MTB{
	meta:
		description = "Trojan:Win64/PixelKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb ff 15 ?? ?? 00 00 66 0f ba e0 ?? 72 ?? ff c3 81 fb ?? ?? ?? ?? 7e ?? 8b 1d 46 45 00 00 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}