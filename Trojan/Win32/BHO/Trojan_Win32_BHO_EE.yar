
rule Trojan_Win32_BHO_EE{
	meta:
		description = "Trojan:Win32/BHO.EE,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 40 70 40 70 20 70 40 72 40 65 6d 24 69 24 75 6d 24 2d 40 6c 69 40 6e 40 6b } //5 c@p@p p@r@em$i$um$-@li@n@k
		$a_01_1 = {46 4f 52 4d 31 5f 41 5f 49 46 52 41 4d 45 } //2 FORM1_A_IFRAME
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}