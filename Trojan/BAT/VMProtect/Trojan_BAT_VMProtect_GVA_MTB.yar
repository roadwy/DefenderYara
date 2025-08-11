
rule Trojan_BAT_VMProtect_GVA_MTB{
	meta:
		description = "Trojan:BAT/VMProtect.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 50 00 00 04 03 07 6a 58 e0 47 06 61 20 ff 00 00 00 5f 95 06 1e 64 61 0a 07 17 58 0b 07 6a 04 6e 3f da ff ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}