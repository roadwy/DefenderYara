
rule Trojan_Win32_Farfli_BAB_MTB{
	meta:
		description = "Trojan:Win32/Farfli.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 ce 8a 14 8f 0f b6 4c 24 14 32 d3 32 4c 24 2c 02 d1 8b 4c 24 10 32 ca 28 0c 28 0f b6 0c 28 89 4c 24 2c 83 e8 01 75 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}