
rule Trojan_BAT_Stealer_A_MTB{
	meta:
		description = "Trojan:BAT/Stealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {24 37 42 45 38 41 32 36 32 2d 41 41 39 46 2d 34 36 46 34 2d 42 44 44 44 2d 31 36 43 34 33 39 34 35 30 33 43 32 } //1 $7BE8A262-AA9F-46F4-BDDD-16C4394503C2
		$a_81_1 = {61 6e 64 72 65 5c 52 69 64 65 72 50 72 6f 6a 65 63 74 73 5c 6d 41 70 70 5c 6d 41 70 70 5c 6f 62 6a } //1 andre\RiderProjects\mApp\mApp\obj
		$a_81_2 = {6d 41 70 70 2e 70 64 62 } //1 mApp.pdb
		$a_01_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 61 00 6e 00 64 00 72 00 75 00 78 00 61 00 2e 00 70 00 70 00 2e 00 75 00 61 00 2f 00 64 00 73 00 66 00 67 00 2f 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 https://andruxa.pp.ua/dsfg/dll.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}