
rule Ransom_AndroidOS_Drokole_A{
	meta:
		description = "Ransom:AndroidOS/Drokole.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 56 69 72 75 73 53 65 61 72 63 68 65 72 3b 00 } //1
		$a_00_1 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 42 61 63 6b 67 72 6f 75 6e 64 53 65 72 76 69 63 65 3b 00 } //1
		$a_00_2 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 42 6f 6f 74 52 65 63 65 69 76 65 72 3b 00 } //1 捌浯愯摮潲摩氯捯敫⽲潂瑯敒散癩牥;
		$a_00_3 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 3b 00 } //1 捌浯愯摮潲摩氯捯敫⽲慍湩捁楴楶祴;
		$a_00_4 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 6c 6f 63 6b 65 72 2f 53 65 6e 64 65 72 41 63 74 69 76 69 74 79 3b 00 } //1 捌浯愯摮潲摩氯捯敫⽲敓摮牥捁楴楶祴;
		$a_00_5 = {69 73 20 6c 6f 63 6b 65 64 20 64 75 65 20 74 6f 20 74 68 65 20 76 69 6f 6c 61 74 69 6f 6e 20 6f 66 20 74 68 65 20 66 65 64 65 72 61 6c 20 6c 61 77 73 20 6f 66 20 74 68 65 20 55 6e 69 74 65 64 20 53 74 61 74 65 73 20 6f 66 20 41 6d 65 72 69 63 61 3a } //1 is locked due to the violation of the federal laws of the United States of America:
		$a_00_6 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 6c 6f 63 6b 2f 42 6f 6f 74 52 65 63 65 69 76 65 72 3b 00 } //1 捌浯支慸灭敬琯獥汴捯⽫潂瑯敒散癩牥;
		$a_00_7 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 6c 6f 63 6b 2f 4c 6f 77 4c 65 76 65 6c 00 } //1
		$a_00_8 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 6c 6f 63 6b 2f 52 65 71 75 65 73 74 53 65 6e 64 65 72 00 } //1 捌浯支慸灭敬琯獥汴捯⽫敒畱獥却湥敤r
		$a_00_9 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 74 65 73 74 6c 6f 63 6b 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 3b 00 } //1 捌浯支慸灭敬琯獥汴捯⽫慍湩捁楴楶祴;
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=3
 
}