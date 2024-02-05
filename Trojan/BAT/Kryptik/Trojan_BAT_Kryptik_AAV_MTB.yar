
rule Trojan_BAT_Kryptik_AAV_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.AAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {19 8d 0d 00 00 01 25 16 7e 90 02 02 00 00 04 a2 25 17 7e 90 02 02 00 00 04 a2 25 18 72 90 02 03 70 a2 90 00 } //02 00 
		$a_80_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //FromBase64String  02 00 
		$a_80_2 = {53 74 72 52 65 76 65 72 73 65 } //StrReverse  02 00 
		$a_80_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //CreateInstance  00 00 
	condition:
		any of ($a_*)
 
}