
rule Trojan_BAT_Crysan_ARA_MTB{
	meta:
		description = "Trojan:BAT/Crysan.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 1f 20 3c ?? ?? ?? 00 07 08 18 5b 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 38 ?? ?? ?? 00 08 18 5b 1f 10 59 0d 06 09 03 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 07 09 07 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f ?? ?? ?? 0a 3f } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}