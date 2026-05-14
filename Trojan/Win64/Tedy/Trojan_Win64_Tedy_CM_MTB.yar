
rule Trojan_Win64_Tedy_CM_MTB{
	meta:
		description = "Trojan:Win64/Tedy.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 8b c3 48 8b d6 48 8b cf ff 15 } //5
		$a_01_1 = {45 33 c9 45 33 c0 ba 00 00 00 40 49 8b cf ff 15 } //5
		$a_01_2 = {48 8b cf ff 15 } //5
		$a_03_3 = {48 8d 4c 24 ?? ff 15 } //5
		$a_01_4 = {72 00 75 00 6e 00 61 00 73 00 } //1 runas
		$a_01_5 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 } //1 msiexec.exe
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_03_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=22
 
}