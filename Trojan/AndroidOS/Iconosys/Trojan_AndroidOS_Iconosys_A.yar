
rule Trojan_AndroidOS_Iconosys_A{
	meta:
		description = "Trojan:AndroidOS/Iconosys.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 07 00 00 "
		
	strings :
		$a_01_0 = {53 65 6e 64 41 75 74 6f 50 68 6f 6e 65 44 61 74 61 } //1 SendAutoPhoneData
		$a_01_1 = {62 6c 61 63 6b 66 6c 79 64 61 79 2e 63 6f 6d 2f 6e 65 77 2f } //1 blackflyday.com/new/
		$a_01_2 = {73 6d 73 72 65 70 6c 69 65 72 2e 63 6f 6d 2f 66 6c 79 } //1 smsreplier.com/fly
		$a_01_3 = {64 65 61 6c 73 2e 64 65 61 6c 62 75 7a 7a 65 72 2e 6e 65 74 2f 69 63 6f 6e 6f 73 79 73 2e 4a 50 47 } //1 deals.dealbuzzer.net/iconosys.JPG
		$a_01_4 = {69 63 6f 6e 6f 73 79 73 65 6d 61 69 6c 40 72 6f 63 6b 65 74 6d 61 69 6c 2e 63 6f 6d } //1 iconosysemail@rocketmail.com
		$a_01_5 = {53 65 6e 64 54 6f 41 75 74 6f 53 65 72 76 65 72 54 61 73 6b } //1 SendToAutoServerTask
		$a_01_6 = {54 6f 70 20 6f 27 20 74 68 65 20 6d 6f 72 6e 69 6e 27 20 61 6e 64 20 61 6c 6c 20 64 61 79 20 74 6f 6f 21 20 4d 61 79 20 74 68 65 20 6c 75 63 6b 20 62 65 20 73 68 69 6e 69 6e 27 20 6f 6e 20 75 21 20 48 61 70 70 79 20 53 74 2e 20 50 61 74 72 69 63 6b 27 73 20 44 61 79 21 } //1 Top o' the mornin' and all day too! May the luck be shinin' on u! Happy St. Patrick's Day!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=2
 
}