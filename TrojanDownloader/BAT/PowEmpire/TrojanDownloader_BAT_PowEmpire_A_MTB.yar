
rule TrojanDownloader_BAT_PowEmpire_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/PowEmpire.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 00 6b 00 41 00 62 00 67 00 42 00 32 00 41 00 47 00 38 00 41 00 61 00 77 00 42 00 6c 00 } //2 EkAbgB2AG8AawBl
		$a_01_1 = {42 00 48 00 41 00 47 00 55 00 41 00 64 00 41 00 42 00 } //2 BHAGUAdAB
		$a_01_2 = {41 00 42 00 45 00 41 00 47 00 45 00 41 00 64 00 41 00 42 00 68 00 41 00 43 00 } //2 ABEAGEAdABhAC
		$a_01_3 = {42 00 37 00 41 00 44 00 49 00 41 00 66 00 51 00 42 00 37 00 41 00 44 00 45 00 41 00 66 00 51 00 42 00 37 00 41 00 44 00 41 00 41 00 66 00 51 00 } //2 B7ADIAfQB7ADEAfQB7ADAAfQ
		$a_01_4 = {41 64 64 53 63 72 69 70 74 } //1 AddScript
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=9
 
}