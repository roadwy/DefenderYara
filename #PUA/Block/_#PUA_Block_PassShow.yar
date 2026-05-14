
rule _#PUA_Block_PassShow{
	meta:
		description = "!#PUA:Block:PassShow,SIGNATURE_TYPE_PEHSTR,03 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 67 65 3a 20 6f 70 68 63 72 61 63 6b } //1 Usage: ophcrack
		$a_01_1 = {43 72 61 63 6b 73 20 57 69 6e 64 6f 77 73 20 70 61 73 73 77 6f 72 64 73 20 77 69 74 68 20 52 61 69 6e 62 6f 77 20 74 61 62 6c 65 73 } //1 Cracks Windows passwords with Rainbow tables
		$a_01_2 = {72 65 61 64 69 6e 67 20 74 68 65 20 53 41 4d 20 66 69 6c 65 } //1 reading the SAM file
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}