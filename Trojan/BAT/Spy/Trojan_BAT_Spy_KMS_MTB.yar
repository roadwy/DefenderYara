
rule Trojan_BAT_Spy_KMS_MTB{
	meta:
		description = "Trojan:BAT/Spy.KMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {73 41 00 00 0a 0b 07 1f 10 8d 38 00 00 01 25 d0 0c 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 1f 10 8d 38 00 00 01 25 d0 0d 00 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 03 16 03 8e 69 6f ?? ?? ?? 0a 0a de 0c 00 07 2c 07 07 6f ?? ?? ?? 0a 00 dc 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}