
rule Trojan_Win32_Dwinup_A{
	meta:
		description = "Trojan:Win32/Dwinup.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 69 63 72 6f 73 6f 66 74 2e 44 69 72 65 63 74 4d 75 73 69 63 53 79 6e 63 68 } //1 Microsoft.DirectMusicSynch
		$a_01_1 = {42 43 39 36 38 42 30 33 2d 45 42 44 45 2d 34 30 66 37 2d 38 39 33 34 2d 38 38 38 46 35 45 45 33 30 41 35 43 } //1 BC968B03-EBDE-40f7-8934-888F5EE30A5C
		$a_01_2 = {50 61 72 74 65 6e 65 72 4e 61 6d 65 } //1 PartenerName
		$a_01_3 = {77 69 6e 75 70 64 2e 44 4c 4c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //1 楷畮摰䐮䱌䐀汬慃啮汮慯乤睯
		$a_01_4 = {44 65 66 61 75 6c 74 5f 50 61 67 65 5f 55 52 4c } //1 Default_Page_URL
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}