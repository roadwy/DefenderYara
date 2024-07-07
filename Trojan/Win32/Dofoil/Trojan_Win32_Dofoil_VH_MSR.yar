
rule Trojan_Win32_Dofoil_VH_MSR{
	meta:
		description = "Trojan:Win32/Dofoil.VH!MSR,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {52 6f 64 65 76 61 6e 2e 20 4c 75 66 65 79 61 6c 75 77 61 68 6f 62 20 74 61 6d 20 78 61 6b 20 6b 61 66 6f 64 61 67 69 62 75 62 75 73 20 77 75 79 6f 76 69 6d 75 2e 20 47 61 76 65 2e 20 54 65 7a 75 6d 65 73 65 78 6f 67 6f 6a 6f 2e 20 50 65 74 75 78 75 77 6f 2e } //Rodevan. Lufeyaluwahob tam xak kafodagibubus wuyovimu. Gave. Tezumesexogojo. Petuxuwo.  1
		$a_80_1 = {68 75 72 75 67 61 6d 65 73 61 70 6f 78 75 67 69 6b 6f } //hurugamesapoxugiko  1
		$a_80_2 = {56 4f 59 4f 44 45 4c 4f 52 55 56 41 4c 49 58 45 4b 45 43 4f 52 4f 43 55 42 45 4a 55 47 49 42 45 } //VOYODELORUVALIXEKECOROCUBEJUGIBE  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}