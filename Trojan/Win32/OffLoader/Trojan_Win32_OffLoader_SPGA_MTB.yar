
rule Trojan_Win32_OffLoader_SPGA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {76 00 65 00 69 00 6c 00 6f 00 72 00 61 00 6e 00 67 00 65 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 62 00 6c 00 69 00 70 00 2e 00 70 00 68 00 70 00 } //3 veilorange.website/blip.php
		$a_01_1 = {61 00 64 00 64 00 69 00 74 00 69 00 6f 00 6e 00 77 00 72 00 69 00 74 00 69 00 6e 00 67 00 2e 00 73 00 69 00 74 00 65 00 2f 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 2f 00 74 00 68 00 61 00 6e 00 6b 00 5f 00 79 00 6f 00 75 00 2e 00 70 00 68 00 70 00 } //2 additionwriting.site/tracker/thank_you.php
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}