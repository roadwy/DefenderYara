
rule Trojan_WinNT_Adwind_YA_MTB{
	meta:
		description = "Trojan:WinNT/Adwind.YA!MTB,SIGNATURE_TYPE_JAVAHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 62 66 72 6f 73 74 2e 6c 69 76 65 2f 73 74 72 69 67 6f 69 2f 6c 69 62 2e 7a 69 70 } //1 jbfrost.live/strigoi/lib.zip
		$a_00_1 = {73 74 72 2d 6d 61 73 74 65 72 2e 70 77 2f 73 74 72 69 67 6f 69 2f 6c 69 62 2e 7a 69 70 } //1 str-master.pw/strigoi/lib.zip
		$a_00_2 = {41 4c 4c 41 54 4f 52 49 78 44 45 4d 4f } //1 ALLATORIxDEMO
		$a_00_3 = {73 74 72 70 61 79 6c 6f 61 64 } //1 strpayload
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}