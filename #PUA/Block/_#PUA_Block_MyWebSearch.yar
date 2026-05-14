
rule _#PUA_Block_MyWebSearch{
	meta:
		description = "!#PUA:Block:MyWebSearch,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {4d 61 70 73 47 61 6c 61 78 79 41 75 74 6f 2e 65 78 65 } //1 MapsGalaxyAuto.exe
		$a_01_1 = {54 6f 6f 6c 62 61 72 20 70 6f 77 65 72 65 64 20 62 79 20 41 73 6b } //2 Toolbar powered by Ask
		$a_01_2 = {3a 2f 2f 65 75 6c 61 2e 6d 69 6e 64 73 70 61 72 6b 2e 63 6f 6d 2f 61 73 6b 2f } //1 ://eula.mindspark.com/ask/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}