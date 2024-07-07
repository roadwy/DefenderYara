
rule Trojan_AndroidOS_FakeApp_M_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeApp.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {73 65 43 2f 6d 79 76 79 76 68 75 75 2f 43 75 69 69 75 64 77 75 68 } //3 seC/myvyvhuu/Cuiiudwuh
		$a_01_1 = {63 6f 6d 2f 6f 6e 6c 69 6e 65 76 6f 69 63 65 2f 70 6c 61 79 65 72 61 70 70 } //3 com/onlinevoice/playerapp
		$a_01_2 = {73 65 43 2f 71 64 74 68 65 79 74 2f 6c 65 42 42 75 4f } //3 seC/qdtheyt/leBBuO
		$a_01_3 = {66 69 6c 65 2e 64 65 6c 65 74 65 } //1 file.delete
		$a_01_4 = {73 65 74 6a 61 76 61 73 63 72 69 70 74 65 6e 61 62 6c 65 64 } //1 setjavascriptenabled
		$a_01_5 = {75 70 6c 6f 61 64 4d 73 67 } //1 uploadMsg
		$a_01_6 = {78 71 64 74 42 75 70 75 69 69 71 77 75 } //1 xqdtBupuiiqwu
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}