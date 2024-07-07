
rule Trojan_BAT_FakeAV_SG_MTB{
	meta:
		description = "Trojan:BAT/FakeAV.SG!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 6c 65 78 69 67 6c 61 73 73 5f 4c 6f 61 64 } //1 plexiglass_Load
		$a_01_1 = {54 6f 74 61 6c 20 41 6e 74 69 76 69 72 75 73 2e 65 78 65 } //1 Total Antivirus.exe
		$a_01_2 = {5c 00 74 00 65 00 6d 00 70 00 5c 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 2e 00 65 00 78 00 65 00 } //1 \temp\Assembly.exe
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 } //1 DisableAntiSpyware
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}