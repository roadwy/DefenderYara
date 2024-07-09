
rule Ransom_Win32_Criakl_A{
	meta:
		description = "Ransom:Win32/Criakl.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {7b 43 52 59 50 54 45 4e 44 42 4c 41 43 4b 44 43 7d } //2 {CRYPTENDBLACKDC}
		$a_01_1 = {7b 43 52 59 50 54 46 55 4c 4c 45 4e 44 } //1 {CRYPTFULLEND
		$a_01_2 = {7b 43 52 59 50 54 53 54 41 52 54 44 41 54 41 7d } //1 {CRYPTSTARTDATA}
		$a_00_3 = {6e 6f 74 74 68 69 73 6f 70 65 72 61 74 69 6f 6e 69 73 61 79 } //1 notthisoperationisay
		$a_00_4 = {3a 2a 2e 6d 64 66 3a 2a 2e 78 6c 73 3a 2a 2e 44 54 3a } //1 :*.mdf:*.xls:*.DT:
		$a_02_5 = {7b 4d 59 49 44 7d [0-10] 7b 4d 59 4d 41 49 4c 7d } //1
		$a_00_6 = {2a 2e 70 70 74 78 7c 7c 7c 7b 7d 7c 7c 7c 30 30 30 } //1 *.pptx|||{}|||000
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}