
rule Trojan_BAT_AsyncRat_DAV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.DAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? 00 06 04 08 18 58 17 59 04 8e 69 5d 91 59 20 } //3
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}