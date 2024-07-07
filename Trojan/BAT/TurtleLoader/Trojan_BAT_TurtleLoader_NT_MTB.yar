
rule Trojan_BAT_TurtleLoader_NT_MTB{
	meta:
		description = "Trojan:BAT/TurtleLoader.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 10 00 00 0a 0c 06 08 07 6f 90 01 01 00 00 06 0d 7e 90 01 01 00 00 0a 09 8e 69 7e 90 01 01 00 00 04 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 13 04 09 16 11 04 09 8e 69 28 90 01 01 00 00 0a 1f 18 16 28 90 01 01 00 00 06 28 90 01 01 00 00 06 13 05 11 04 11 05 7e 90 01 01 00 00 0a 28 90 01 01 00 00 06 90 00 } //5
		$a_01_1 = {61 70 6f 6f 6c 2e 65 78 65 } //1 apool.exe
		$a_01_2 = {7a 68 75 64 6f 6e 67 66 61 6e 67 79 75 } //1 zhudongfangyu
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}