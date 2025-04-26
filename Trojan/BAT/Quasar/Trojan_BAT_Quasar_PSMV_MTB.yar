
rule Trojan_BAT_Quasar_PSMV_MTB{
	meta:
		description = "Trojan:BAT/Quasar.PSMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {28 0c 00 00 0a 72 3d 00 00 70 28 ?? ?? ?? 0a 13 05 38 47 00 00 00 73 ?? ?? ?? 0a 25 11 05 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 20 00 00 00 00 7e 10 00 00 04 7b 18 00 00 04 39 aa ff ff ff 26 20 00 00 00 00 38 9f ff ff ff 11 05 11 02 28 ?? ?? ?? 0a 38 b9 ff ff ff 11 04 72 47 00 00 70 6f ?? ?? ?? 0a 13 02 38 df ff ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}