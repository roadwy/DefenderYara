
rule Trojan_Win64_Lazy_ABYV_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ABYV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {46 6a 69 6f 63 6f 69 76 6a 73 66 69 69 71 77 69 } //02 00  Fjiocoivjsfiiqwi
		$a_01_1 = {52 6f 69 61 69 66 61 65 6a 66 38 39 61 6a 64 69 67 73 64 63 6a } //02 00  Roiaifaejf89ajdigsdcj
		$a_01_2 = {74 69 6d 65 47 65 74 54 69 6d 65 } //00 00  timeGetTime
	condition:
		any of ($a_*)
 
}