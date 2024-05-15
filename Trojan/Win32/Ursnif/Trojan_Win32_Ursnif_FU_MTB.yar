
rule Trojan_Win32_Ursnif_FU_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.FU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 65 63 6f 78 69 20 72 69 70 6f 6b 65 6e 65 67 61 68 6f 6b 75 20 67 6f 6c 65 20 72 65 6a 6f 6e 6f 70 69 6a 65 79 69 20 62 69 72 75 66 75 79 65 } //01 00  Hecoxi ripokenegahoku gole rejonopijeyi birufuye
		$a_01_1 = {4b 6f 76 75 74 65 6d 69 70 69 20 67 6f 63 75 } //01 00  Kovutemipi gocu
		$a_01_2 = {4b 6f 74 69 78 61 77 6f 79 75 67 75 6b 75 66 6f 20 76 69 66 61 74 6f 7a 6f 6d 61 62 65 6d 75 20 66 69 20 6a 75 79 6f 20 70 65 78 61 7a 69 6b 69 78 69 6e 6f 63 6f 20 79 6f 7a 65 70 69 67 65 70 75 79 61 20 64 69 72 75 } //01 00  Kotixawoyugukufo vifatozomabemu fi juyo pexazikixinoco yozepigepuya diru
		$a_01_3 = {46 6f 76 65 63 6f 74 69 72 65 74 6f 20 70 61 67 6f 6a 65 72 6f 79 69 70 61 20 72 6f 63 6f 77 6f 64 6f 6b 6f 20 73 6f 6b 69 20 77 75 67 61 72 69 79 65 79 6f } //00 00  Fovecotireto pagojeroyipa rocowodoko soki wugariyeyo
	condition:
		any of ($a_*)
 
}