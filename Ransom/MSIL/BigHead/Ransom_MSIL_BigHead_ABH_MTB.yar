
rule Ransom_MSIL_BigHead_ABH_MTB{
	meta:
		description = "Ransom:MSIL/BigHead.ABH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 2b 14 00 02 09 11 04 9a 04 28 90 01 03 06 00 00 11 04 17 58 13 04 11 04 09 8e 69 fe 04 13 09 11 09 2d df 90 00 } //2
		$a_01_1 = {73 6c 61 6d 5f 72 61 6e 73 6f 6d 77 61 72 65 5f 62 75 69 6c 64 65 72 5c 43 6f 6e 73 6f 6c 65 41 70 70 32 5c 43 6f 6e 73 6f 6c 65 41 70 70 32 5c 6f 62 6a 5c 44 65 62 75 67 5c 43 6f 6e 73 6f 6c 65 41 70 70 32 2e 70 64 62 } //1 slam_ransomware_builder\ConsoleApp2\ConsoleApp2\obj\Debug\ConsoleApp2.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}