
rule Ransom_MSIL_HiddenTear_TH_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.TH!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 \Startup\svchost.exe
		$a_01_1 = {5a 00 46 00 49 00 52 00 45 00 20 00 48 00 41 00 53 00 20 00 49 00 4e 00 46 00 45 00 43 00 54 00 45 00 44 00 20 00 55 00 52 00 20 00 50 00 4f 00 4f 00 50 00 48 00 4f 00 4c 00 45 00 } //1 ZFIRE HAS INFECTED UR POOPHOLE
		$a_01_2 = {43 00 68 00 65 00 63 00 6b 00 69 00 6e 00 67 00 20 00 69 00 66 00 20 00 79 00 6f 00 75 00 20 00 68 00 61 00 76 00 65 00 20 00 70 00 61 00 79 00 65 00 64 00 2e 00 } //1 Checking if you have payed.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}