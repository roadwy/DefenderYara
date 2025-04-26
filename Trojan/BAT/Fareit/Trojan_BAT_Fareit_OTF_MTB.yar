
rule Trojan_BAT_Fareit_OTF_MTB{
	meta:
		description = "Trojan:BAT/Fareit.OTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 01 00 00 04 07 7e 01 00 00 04 07 91 7e 02 00 00 04 07 7e 02 00 00 04 8e 69 5d 91 07 06 58 7e 02 00 00 04 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 07 17 58 0b 07 7e 01 00 00 04 8e 69 32 bd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}