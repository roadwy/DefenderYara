
rule Trojan_O97M_Malgent_RV_MTB{
	meta:
		description = "Trojan:O97M/Malgent.RV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 6d 73 78 6d 6c 32 2e 78 6d 6c 68 74 74 70 22 29 68 74 74 70 5f 6f 62 6a 2e 6f 70 65 6e 22 70 6f 73 74 22 2c 22 68 74 74 70 3a 2f 2f 31 38 38 2e 31 33 30 2e 32 33 34 2e 31 38 39 2f 77 61 69 74 2e 70 68 70 } //1 =createobject("msxml2.xmlhttp")http_obj.open"post","http://188.130.234.189/wait.php
		$a_01_1 = {73 70 6c 69 74 28 74 65 6d 70 5f 73 74 72 2c 22 23 23 23 22 29 } //1 split(temp_str,"###")
		$a_01_2 = {73 75 62 64 6f 63 75 6d 65 6e 74 5f 6f 70 65 6e 28 29 } //1 subdocument_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}