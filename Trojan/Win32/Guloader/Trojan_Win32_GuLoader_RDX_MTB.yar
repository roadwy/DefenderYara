
rule Trojan_Win32_GuLoader_RDX_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {5c 44 6f 6b 74 6f 72 72 69 6e 67 65 73 5c 70 65 6b 74 69 6e 5c 70 65 72 66 65 63 74 69 6f 6e } //1 \Doktorringes\pektin\perfection
		$a_81_1 = {5c 72 65 77 65 69 67 68 65 72 5c 72 65 76 65 74 6d 65 6e 74 73 2e 74 78 74 } //1 \reweigher\revetments.txt
		$a_81_2 = {63 61 73 68 6d 65 72 65 20 67 65 6e 65 72 65 72 69 6e 67 65 72 73 20 63 6f 75 6e 74 65 72 64 69 67 67 65 64 } //1 cashmere genereringers counterdigged
		$a_81_3 = {72 75 62 72 69 63 61 6c 69 74 79 } //1 rubricality
		$a_81_4 = {68 61 63 6b 6e 65 79 6d 61 6e } //1 hackneyman
		$a_81_5 = {72 61 79 2e 65 78 65 } //1 ray.exe
		$a_81_6 = {63 72 65 70 69 64 6f 6d 61 5c 75 6e 73 74 65 65 6c 65 64 2e 65 78 65 } //1 crepidoma\unsteeled.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}