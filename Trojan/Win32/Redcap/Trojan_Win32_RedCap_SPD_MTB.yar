
rule Trojan_Win32_RedCap_SPD_MTB{
	meta:
		description = "Trojan:Win32/RedCap.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {4e 6f 61 64 66 67 69 6f 61 65 6a 66 69 67 6f 61 65 66 } //2 Noadfgioaejfigoaef
		$a_01_1 = {4e 6f 65 61 6a 69 6f 66 67 73 65 61 6a 69 67 66 65 73 69 66 67 } //2 Noeajiofgseajigfesifg
		$a_01_2 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //1 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}