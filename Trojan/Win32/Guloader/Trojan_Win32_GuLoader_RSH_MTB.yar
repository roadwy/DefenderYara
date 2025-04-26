
rule Trojan_Win32_GuLoader_RSH_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {61 6d 79 67 64 61 6c 65 5c 55 69 6e 69 74 69 61 6c 69 73 65 72 65 74 5c 72 65 73 74 72 69 6b 74 69 76 69 74 65 74 65 6e 73 } //1 amygdale\Uinitialiseret\restriktivitetens
		$a_81_1 = {23 5c 53 65 6c 76 68 6a 74 69 64 65 6c 69 67 5c 63 61 6c 6f 64 65 6d 6f 6e 69 61 6c 2e 69 6e 69 } //1 #\Selvhjtidelig\calodemonial.ini
		$a_81_2 = {5c 6d 65 67 61 61 72 61 2e 43 65 72 } //1 \megaara.Cer
		$a_81_3 = {66 72 65 6b 76 65 6e 73 6f 6d 72 61 61 64 65 72 6e 65 20 67 6c 69 61 64 69 6e 65 73 } //1 frekvensomraaderne gliadines
		$a_81_4 = {70 72 65 63 6f 6e 74 65 6e 74 69 6f 6e 20 75 6e 70 65 72 66 6f 72 61 74 69 6e 67 } //1 precontention unperforating
		$a_81_5 = {61 6e 64 65 64 61 6d 6d 65 6e 65 20 65 6c 65 6b 74 72 6f 6e 72 72 65 74 } //1 andedammene elektronrret
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}