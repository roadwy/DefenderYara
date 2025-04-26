
rule Trojan_Win32_Glupteba_ASH_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 65 6d 69 77 61 70 75 62 69 78 6f 6b 65 76 61 6a 75 7a 61 6e 75 70 65 68 20 74 69 66 69 6a 20 66 75 66 65 73 75 77 75 70 61 74 61 6d 75 79 75 76 65 } //1 nemiwapubixokevajuzanupeh tifij fufesuwupatamuyuve
		$a_01_1 = {70 75 62 61 62 6f 74 20 70 69 76 61 6e 65 6e 69 67 75 79 6f 6b 6f 20 62 69 77 6f 7a 65 6e 69 78 75 66 65 66 65 72 20 67 75 64 61 6a 6f 68 61 7a 6f 6b 6f 7a 69 73 75 6a 6f 63 20 64 75 6b 65 66 6f 7a 61 74 75 76 69 68 6f 6e 69 } //1 pubabot pivaneniguyoko biwozenixufefer gudajohazokozisujoc dukefozatuvihoni
		$a_01_2 = {79 6f 67 6f 72 69 70 61 6a 6f 72 75 78 75 72 65 70 69 6e 65 64 61 66 61 } //1 yogoripajoruxurepinedafa
		$a_01_3 = {7a 75 6a 61 70 69 6a 6f 76 6f 77 61 73 65 6b 75 68 65 79 61 64 69 74 75 73 61 } //1 zujapijovowasekuheyaditusa
		$a_01_4 = {63 75 78 61 62 75 67 61 7a 65 6e 20 6d 75 7a 6f 6d 65 78 75 6c 61 73 65 77 75 74 69 63 6f 62 61 6a 20 7a 6f 78 75 70 65 66 75 20 62 65 6e 61 78 6f 6e 69 79 6f 6b 6f 6b 69 64 } //1 cuxabugazen muzomexulasewuticobaj zoxupefu benaxoniyokokid
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}