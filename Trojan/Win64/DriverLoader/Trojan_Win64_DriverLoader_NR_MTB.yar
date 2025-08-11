
rule Trojan_Win64_DriverLoader_NR_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {88 54 24 10 88 4c 24 08 48 83 ec ?? 0f b6 05 5d b0 06 00 85 c0 74 0d } //2
		$a_01_1 = {4d 79 57 46 48 61 63 6b 5c 43 72 79 4b 69 6c 6c 65 72 5c 4e 45 57 20 42 59 50 41 53 53 5c 77 31 6e 6e 65 72 } //1 MyWFHack\CryKiller\NEW BYPASS\w1nner
		$a_01_2 = {6c 69 6d 69 74 65 64 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 77 31 6e 6e 65 72 2e 70 64 62 } //1 limited\x64\Release\w1nner.pdb
		$a_01_3 = {68 00 69 00 64 00 65 00 } //1 hide
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}