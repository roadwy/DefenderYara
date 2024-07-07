
rule Trojan_Win64_BeaverTail_RPX_MTB{
	meta:
		description = "Trojan:Win64/BeaverTail.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 db 4c 89 65 07 48 8d 45 0f 89 75 ff 48 89 44 24 30 48 8d 4d ff 45 33 c9 89 5c 24 28 45 33 c0 48 89 5c 24 20 33 d2 45 84 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}