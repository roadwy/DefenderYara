
rule Trojan_Win32_Dridex_KF_MTB{
	meta:
		description = "Trojan:Win32/Dridex.KF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 06 00 00 "
		
	strings :
		$a_80_0 = {74 68 61 74 73 69 74 65 73 2e 63 6f 66 77 35 43 68 72 6f 6d 65 6d 6f 6e 65 79 43 68 72 6f 6d 65 70 } //thatsites.cofw5ChromemoneyChromep  3
		$a_80_1 = {67 72 65 67 6f 72 79 74 68 65 48 48 54 4d 4c 35 74 68 65 74 68 65 66 61 6e 6e 6f 75 6e 63 65 64 66 69 72 73 74 } //gregorytheHHTML5thethefannouncedfirst  3
		$a_80_2 = {35 33 66 72 6f 6d 59 47 74 68 65 74 68 65 } //53fromYGthethe  3
		$a_80_3 = {45 53 20 41 50 50 20 45 5f } //ES APP E_  3
		$a_80_4 = {68 6f 6f 74 65 72 73 66 6f 72 31 39 31 37 55 6f 66 46 38 28 4e 50 41 50 49 29 } //hootersfor1917UofF8(NPAPI)  3
		$a_80_5 = {37 31 35 35 77 68 69 63 68 65 78 69 73 74 69 6e 67 74 6f 68 65 61 74 68 65 72 66 65 65 73 47 65 61 72 73 74 68 65 6d 65 73 73 6f } //7155whichexistingtoheatherfeesGearsthemesso  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=18
 
}