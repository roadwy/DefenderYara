
rule Trojan_BAT_BlackFus_A{
	meta:
		description = "Trojan:BAT/BlackFus.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 1f 20 2f ?? 07 08 18 5b 03 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 9c 2b ?? 08 18 5b 1f 10 59 0d 06 09 03 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 07 09 07 8e 69 5d 91 61 d2 9c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}