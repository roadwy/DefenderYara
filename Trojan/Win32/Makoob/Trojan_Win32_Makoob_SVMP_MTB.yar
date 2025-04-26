
rule Trojan_Win32_Makoob_SVMP_MTB{
	meta:
		description = "Trojan:Win32/Makoob.SVMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_81_0 = {42 69 66 6c 6f 64 65 72 6e 65 39 30 2e 69 6e 69 } //2 Bifloderne90.ini
		$a_81_1 = {68 6a 65 6d 6f 6d 2e 6d 75 6e } //2 hjemom.mun
		$a_81_2 = {49 6e 74 65 72 70 6c 65 61 64 65 72 35 35 2e 72 69 6b } //2 Interpleader55.rik
		$a_81_3 = {64 6f 62 62 65 6c 74 62 65 76 69 64 73 74 68 65 64 73 2e 74 78 74 } //1 dobbeltbevidstheds.txt
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*1) >=7
 
}