
rule Trojan_BAT_JellyfishLoader_AJL_MTB{
	meta:
		description = "Trojan:BAT/JellyfishLoader.AJL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {2c 02 17 2a 00 03 73 ?? 00 00 0a 28 ?? 00 00 06 2c 0a 17 80 ?? 00 00 04 17 0a de 09 16 0a de 05 26 16 0a } //2
		$a_01_1 = {32 36 39 64 35 33 61 38 2d 38 35 33 32 2d 34 39 66 66 2d 61 33 31 30 2d 34 34 38 36 35 62 33 62 30 64 62 38 } //1 269d53a8-8532-49ff-a310-44865b3b0db8
		$a_01_2 = {6a 65 6c 6c 79 66 69 73 68 5c 4a 65 6c 6c 79 66 69 73 68 4c 6f 61 64 65 72 5c 6f 62 6a 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 71 65 6d 75 2d 67 61 2e 70 64 62 } //1 jellyfish\JellyfishLoader\obj\x64\Release\qemu-ga.pdb
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}