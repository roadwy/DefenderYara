
rule Ransom_Win32_BlackByte_SA{
	meta:
		description = "Ransom:Win32/BlackByte.SA,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 0a 00 00 "
		
	strings :
		$a_80_0 = {6d 61 69 6e 2e 64 65 6c 73 68 61 64 6f 77 73 } //main.delshadows  5
		$a_80_1 = {6d 61 69 6e 2e 73 74 6f 70 61 6c 6c 73 76 63 } //main.stopallsvc  5
		$a_80_2 = {6d 61 69 6e 2e 6b 69 6c 6c } //main.kill  5
		$a_80_3 = {6d 61 69 6e 2e 65 6e 63 72 79 70 74 } //main.encrypt  5
		$a_80_4 = {6d 61 69 6e 2e 64 65 73 74 72 6f 79 } //main.destroy  5
		$a_80_5 = {6d 61 69 6e 2e 6c 69 73 74 73 65 72 76 69 63 65 73 } //main.listservices  5
		$a_80_6 = {6d 61 69 6e 2e 6c 61 6e 73 63 61 6e } //main.lanscan  5
		$a_80_7 = {6d 61 69 6e 2e 70 61 72 73 65 6e 65 74 76 69 65 77 } //main.parsenetview  5
		$a_80_8 = {6d 61 69 6e 2e 73 68 6f 77 6e 6f 74 65 } //main.shownote  5
		$a_80_9 = {6d 61 69 6e 2e 70 6f 67 6e 61 6c 69 } //main.pognali  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_80_3  & 1)*5+(#a_80_4  & 1)*5+(#a_80_5  & 1)*5+(#a_80_6  & 1)*5+(#a_80_7  & 1)*5+(#a_80_8  & 1)*5+(#a_80_9  & 1)*5) >=30
 
}