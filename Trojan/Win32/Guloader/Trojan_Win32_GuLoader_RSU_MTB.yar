
rule Trojan_Win32_GuLoader_RSU_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {5c 53 6b 6f 6c 69 6e 67 73 5c 4c 6f 67 69 6b 6b 65 72 6e 65 31 30 31 5c 63 68 69 72 6f 6c 6f 67 69 65 73 } //1 \Skolings\Logikkerne101\chirologies
		$a_81_1 = {73 79 6e 61 78 61 72 5c 6e 6f 6e 76 69 72 74 75 6f 75 73 6e 65 73 73 5c 72 65 73 61 63 61 } //1 synaxar\nonvirtuousness\resaca
		$a_81_2 = {35 5c 74 69 6c 62 61 67 65 64 61 74 65 72 69 6e 67 65 72 6e 65 73 5c 46 6f 72 72 65 76 6e 65 73 32 32 39 2e 61 66 66 } //1 5\tilbagedateringernes\Forrevnes229.aff
		$a_81_3 = {5c 75 6e 64 65 72 74 69 64 65 5c 62 65 73 73 65 72 6d 61 63 68 65 6e 2e 69 6e 69 } //1 \undertide\bessermachen.ini
		$a_81_4 = {6b 76 72 75 6c 65 72 65 6e 64 65 73 } //1 kvrulerendes
		$a_81_5 = {46 6c 61 67 65 6c 6c 61 6e 74 73 2e 74 78 74 } //1 Flagellants.txt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}