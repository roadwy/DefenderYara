
rule PUA_Win32_ProduKey_Lowfi{
	meta:
		description = "PUA:Win32/ProduKey!Lowfi,SIGNATURE_TYPE_PEHSTR,64 00 64 00 08 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 4e 69 72 53 6f 66 74 5c 50 72 6f 64 75 4b 65 79 00 } //10 潓瑦慷敲乜物潓瑦停潲畤敋y
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 69 72 73 6f 66 74 2e 6e 65 74 2f 75 74 69 6c 73 2f 70 72 6f 64 75 63 74 5f 63 64 5f 6b 65 79 5f 76 69 65 77 65 72 2e 68 74 6d 6c 00 } //10 瑨灴⼺眯睷渮物潳瑦渮瑥甯楴獬瀯潲畤瑣损彤敫役楶睥牥栮浴l
		$a_01_2 = {52 65 6c 65 61 73 65 5c 50 72 6f 64 75 4b 65 79 2e 70 64 62 00 } //10
		$a_01_3 = {2f 53 51 4c 4b 65 79 73 00 } //1
		$a_01_4 = {2f 45 78 63 68 61 6e 67 65 4b 65 79 73 00 } //1 䔯捸慨杮䭥祥s
		$a_01_5 = {2f 69 70 72 61 6e 67 65 00 } //1
		$a_01_6 = {2f 72 65 6d 6f 74 65 66 69 6c 65 00 } //1 爯浥瑯晥汩e
		$a_01_7 = {2f 72 65 6d 6f 74 65 61 6c 6c 64 6f 6d 61 69 6e 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=100
 
}