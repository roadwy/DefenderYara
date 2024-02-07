
rule Trojan_BAT_Ursnif_MBEG_MTB{
	meta:
		description = "Trojan:BAT/Ursnif.MBEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 66 73 64 6b 66 64 68 67 68 66 66 73 68 73 66 65 67 66 64 61 66 66 66 64 63 68 } //01 00  hfsdkfdhghffshsfegfdafffdch
		$a_01_1 = {66 68 68 66 67 64 66 66 72 66 66 66 64 6b 64 66 61 64 68 66 67 68 66 64 61 73 64 66 68 } //01 00  fhhfgdffrfffdkdfadhfghfdasdfh
		$a_01_2 = {66 73 67 66 72 67 66 61 66 64 64 68 64 66 66 66 66 6b 68 73 6a 64 } //01 00  fsgfrgfafddhdffffkhsjd
		$a_01_3 = {73 64 64 64 64 66 66 66 68 65 67 68 64 66 64 6a 66 66 66 66 67 6a 68 73 64 67 73 66 61 61 66 63 73 61 66 70 } //01 00  sddddfffheghdfdjffffgjhsdgsfaafcsafp
		$a_01_4 = {73 68 73 64 73 68 64 73 64 } //01 00  shsdshdsd
		$a_01_5 = {73 66 68 6a 66 66 6b 66 68 67 66 64 6a 73 72 66 68 64 66 64 66 68 66 66 66 61 64 73 67 66 61 68 73 73 63 66 66 67 64 62 } //01 00  sfhjffkfhgfdjsrfhdfdfhfffadsgfahsscffgdb
		$a_01_6 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //00 00  RijndaelManaged
	condition:
		any of ($a_*)
 
}