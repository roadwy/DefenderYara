
rule DDoS_Linux_Lightaidra_D_MTB{
	meta:
		description = "DDoS:Linux/Lightaidra.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {1c f2 ff eb 78 0d 9f e5 ac 1c 9f e5 6c 2f 9f e5 18 f2 ff eb 68 0d 9f e5 98 1c 9f e5 4c 2d 9f e5 14 f2 ff eb 90 1c 9f e5 54 0d 9f e5 01 20 a0 e1 10 f2 ff eb 50 1f 9f e5 44 0d 9f e5 01 20 a0 e1 0c f2 ff eb 38 0d 9f e5 6c 1c 9f e5 f0 2e 9f e5 08 f2 ff eb 28 0d 9f e5 5c 1c 9f e5 4c 2e 9f e5 04 f2 ff eb 18 0d 9f e5 4c 1c 9f e5 4c 2c 9f e5 00 f2 ff eb 08 0d 9f e5 3c 1c 9f e5 84 2c 9f e5 } //2
		$a_01_1 = {50 40 35 35 77 30 72 64 21 } //1 P@55w0rd!
		$a_01_2 = {74 73 75 6e 61 6d 69 } //1 tsunami
		$a_01_3 = {72 6f 6f 74 31 32 33 34 } //1 root1234
	condition:
		((#a_00_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}