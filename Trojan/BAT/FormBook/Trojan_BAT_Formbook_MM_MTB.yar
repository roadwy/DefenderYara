
rule Trojan_BAT_Formbook_MM_MTB{
	meta:
		description = "Trojan:BAT/Formbook.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 4d 4b 6f 72 74 7a } //1 get_MKortz
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {40 00 58 00 41 00 52 00 45 00 61 00 6d 00 40 00 78 00 65 00 74 00 61 00 6c 00 73 00 69 00 2e 00 40 00 58 00 41 00 52 00 45 00 64 00 6c 00 6c 00 } //1 @XAREam@xetalsi.@XAREdll
		$a_01_3 = {3d 00 3d 00 49 00 6e 00 76 00 77 00 5a 00 51 00 3d 00 3d 00 6f 00 6b 00 65 00 } //1 ==InvwZQ==oke
		$a_01_4 = {55 70 6c 6f 61 64 46 69 6c 65 } //1 UploadFile
		$a_01_5 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}