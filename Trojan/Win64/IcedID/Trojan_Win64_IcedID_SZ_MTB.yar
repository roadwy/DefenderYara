
rule Trojan_Win64_IcedID_SZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 66 3b ed 0f 84 90 01 04 48 90 01 02 48 90 01 02 48 90 01 04 66 90 01 02 74 90 01 01 8b 84 24 90 0a 20 00 8b 4c 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}