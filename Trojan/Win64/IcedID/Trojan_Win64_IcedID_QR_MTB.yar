
rule Trojan_Win64_IcedID_QR_MTB{
	meta:
		description = "Trojan:Win64/IcedID.QR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_01_0 = {41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe b8 db 01 00 eb 2d } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}