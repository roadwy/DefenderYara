
rule Trojan_Win32_Snojan_ASFQ_MTB{
	meta:
		description = "Trojan:Win32/Snojan.ASFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 65 63 61 6e 2e 68 61 73 74 68 65 2e 74 65 63 68 6e 6f 6c 6f 67 79 2f 75 70 6c 6f 61 64 } //01 00  wecan.hasthe.technology/upload
		$a_01_1 = {6d 61 20 61 75 20 67 61 20 72 72 65 20 67 79 61 6a 65 20 77 65 65 6c } //01 00  ma au ga rre gyaje weel
		$a_01_2 = {72 69 66 61 69 65 6e 32 2d 25 73 2e 65 78 65 } //01 00  rifaien2-%s.exe
		$a_01_3 = {6d 61 20 6e 75 6d 20 77 61 20 72 69 66 61 69 65 6e 20 79 61 6e 6a 65 } //01 00  ma num wa rifaien yanje
		$a_01_4 = {6d 61 20 6e 75 6d 20 77 61 20 67 79 65 6e 20 6f 72 6e 20 68 79 7a 69 6b 20 25 73 20 65 6e 20 65 78 65 63 20 77 65 65 6e 20 4e 4f 44 45 25 69 } //00 00  ma num wa gyen orn hyzik %s en exec ween NODE%i
	condition:
		any of ($a_*)
 
}