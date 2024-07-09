
rule Trojan_BAT_Remcos_YVR_MTB{
	meta:
		description = "Trojan:BAT/Remcos.YVR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 18 5b 1f 10 59 0d 08 1f 20 2f 16 06 08 18 5b 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 2b 1b 07 09 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 06 09 06 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f ?? ?? ?? 0a 32 b6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}