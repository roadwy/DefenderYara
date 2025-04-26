
rule Trojan_Win32_Glupteba_DE_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {42 00 75 00 6d 00 75 00 66 00 69 00 20 00 68 00 6f 00 6a 00 69 00 76 00 65 00 7a 00 75 00 64 00 69 00 7a 00 20 00 68 00 61 00 76 00 6f 00 6d 00 6f 00 6a 00 75 00 74 00 6f 00 7a 00 20 00 70 00 69 00 72 00 61 00 64 00 69 00 63 00 6f 00 78 00 20 00 72 00 61 00 70 00 69 00 72 00 69 00 6c 00 61 00 6a 00 6f 00 78 00 69 00 7a 00 61 00 6d 00 } //1 Bumufi hojivezudiz havomojutoz piradicox rapirilajoxizam
		$a_01_1 = {46 00 6f 00 6b 00 75 00 6e 00 61 00 77 00 6f 00 70 00 61 00 72 00 6f 00 68 00 61 00 6c 00 20 00 68 00 65 00 66 00 6f 00 6e 00 61 00 63 00 69 00 74 00 20 00 64 00 69 00 67 00 6f 00 76 00 } //1 Fokunawoparohal hefonacit digov
		$a_01_2 = {53 00 61 00 78 00 20 00 6b 00 61 00 77 00 61 00 6c 00 61 00 67 00 69 00 77 00 61 00 6b 00 20 00 79 00 65 00 70 00 65 00 68 00 69 00 6c 00 75 00 66 00 20 00 6a 00 61 00 63 00 6f 00 74 00 61 00 76 00 6f 00 67 00 65 00 6b 00 6f 00 20 00 62 00 69 00 76 00 75 00 70 00 75 00 63 00 6f 00 67 00 65 00 } //1 Sax kawalagiwak yepehiluf jacotavogeko bivupucoge
		$a_01_3 = {4c 00 69 00 76 00 65 00 7a 00 61 00 78 00 61 00 70 00 61 00 6e 00 75 00 77 00 61 00 20 00 63 00 69 00 6e 00 61 00 6a 00 75 00 68 00 65 00 20 00 6a 00 69 00 73 00 65 00 73 00 65 00 6b 00 75 00 68 00 65 00 68 00 75 00 73 00 61 00 20 00 6d 00 75 00 68 00 6f 00 62 00 61 00 78 00 69 00 6d 00 69 00 20 00 76 00 61 00 78 00 6f 00 6b 00 65 00 } //1 Livezaxapanuwa cinajuhe jisesekuhehusa muhobaximi vaxoke
		$a_01_4 = {54 69 74 65 6c 61 6e 75 66 75 20 6d 61 66 61 73 65 72 65 62 65 72 69 79 75 76 20 72 69 79 61 6a 65 78 75 20 6c 65 64 75 62 75 72 61 62 20 66 61 6c 65 79 61 74 6f 73 65 72 } //1 Titelanufu mafasereberiyuv riyajexu leduburab faleyatoser
		$a_01_5 = {47 75 68 69 6c 69 74 75 79 61 67 6f 72 75 6c 20 70 61 6a 69 62 75 7a 69 66 20 6e 65 6e 65 20 76 6f 67 6f 72 65 66 69 74 75 79 6f 74 } //1 Guhilituyagorul pajibuzif nene vogorefituyot
		$a_01_6 = {73 65 70 75 6b 65 66 75 6d 65 6e 69 66 65 73 61 6c 65 72 69 62 65 68 61 6a 61 74 20 70 69 73 6f 6a 75 70 65 73 75 68 65 7a 75 70 65 68 65 73 6f 74 6f 63 75 6e 6f 6d 65 67 75 7a 69 20 6b 65 76 61 74 61 70 6f 62 61 78 61 68 69 76 69 6a 69 } //1 sepukefumenifesaleribehajat pisojupesuhezupehesotocunomeguzi kevatapobaxahiviji
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}