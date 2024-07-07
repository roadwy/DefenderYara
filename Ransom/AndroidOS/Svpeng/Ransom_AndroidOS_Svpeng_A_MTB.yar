
rule Ransom_AndroidOS_Svpeng_A_MTB{
	meta:
		description = "Ransom:AndroidOS/Svpeng.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 63 6f 6d 2f 61 70 69 2f 61 70 70 2e 70 68 70 } //1 .com/api/app.php
		$a_01_1 = {63 6f 75 6e 74 70 68 6f 6e 65 73 } //1 countphones
		$a_01_2 = {6c 69 73 74 70 68 6f 6e 65 73 } //1 listphones
		$a_01_3 = {6b 69 6c 6c 50 72 6f 63 65 73 73 } //1 killProcess
		$a_01_4 = {63 6f 6d 2f 62 72 74 6f 68 65 72 73 6f 66 74 2f 74 72 6e 69 74 79 } //1 com/brtohersoft/trnity
		$a_03_5 = {12 23 54 64 90 01 02 54 65 90 01 02 6e 40 90 01 02 32 54 54 62 90 01 02 71 10 90 01 02 07 00 0c 03 6e 20 90 01 02 32 00 0c 00 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}