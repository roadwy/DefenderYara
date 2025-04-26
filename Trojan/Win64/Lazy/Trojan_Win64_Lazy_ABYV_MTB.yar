
rule Trojan_Win64_Lazy_ABYV_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ABYV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 6a 69 6f 63 6f 69 76 6a 73 66 69 69 71 77 69 } //2 Fjiocoivjsfiiqwi
		$a_01_1 = {52 6f 69 61 69 66 61 65 6a 66 38 39 61 6a 64 69 67 73 64 63 6a } //2 Roiaifaejf89ajdigsdcj
		$a_01_2 = {74 69 6d 65 47 65 74 54 69 6d 65 } //2 timeGetTime
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}