
rule Ransom_Win32_Death_PA_MTB{
	meta:
		description = "Ransom:Win32/Death.PA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 45 41 54 48 52 41 4e 53 4f 4d } //1 DEATHRANSOM
		$a_01_1 = {59 6f 75 72 20 4c 4f 43 4b 2d 49 44 3a 20 25 73 } //1 Your LOCK-ID: %s
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 57 61 63 61 74 61 63 } //1 SOFTWARE\Wacatac
		$a_01_3 = {25 00 73 00 5c 00 72 00 65 00 61 00 64 00 5f 00 6d 00 65 00 2e 00 74 00 78 00 74 00 } //1 %s\read_me.txt
		$a_01_4 = {73 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } //1 select * from Win32_ShadowCopy
		$a_01_5 = {25 00 73 00 2e 00 77 00 63 00 74 00 63 00 } //1 %s.wctc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}