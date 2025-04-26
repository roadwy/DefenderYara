
rule Ransom_MacOS_Turtle_A_MTB{
	meta:
		description = "Ransom:MacOS/Turtle.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 65 6e 30 63 72 30 79 70 30 74 46 69 6c 65 } //1 main.en0cr0yp0tFile
		$a_01_1 = {2f 56 69 72 54 65 73 74 2f 54 75 72 6d 69 52 61 6e 73 6f 6d 2f 6d 61 69 6e 2e 67 6f } //1 /VirTest/TurmiRansom/main.go
		$a_01_2 = {70 61 74 68 2f 66 69 6c 65 70 61 74 68 2e 57 61 6c 6b } //1 path/filepath.Walk
		$a_01_3 = {2e 54 55 52 54 4c 45 52 41 4e 53 76 } //1 .TURTLERANSv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}