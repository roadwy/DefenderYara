
rule Trojan_BAT_Heracles_PPPZ_MTB{
	meta:
		description = "Trojan:BAT/Heracles.PPPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 21 00 00 0a 0c 08 06 07 6f ?? ?? ?? 0a 0d 73 23 00 00 0a 13 04 11 04 09 17 73 24 00 00 0a 13 05 11 05 7e 02 00 00 04 16 7e 02 00 00 04 8e 69 6f ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 80 02 00 00 04 dd 1e 00 00 00 11 05 39 07 00 00 00 11 05 6f ?? ?? ?? 0a dc 11 04 39 07 00 00 00 11 04 6f ?? ?? ?? 0a dc 7e 02 00 00 04 13 06 dd 0d 00 00 00 08 39 06 00 00 00 08 6f ?? ?? ?? 0a dc 11 06 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}