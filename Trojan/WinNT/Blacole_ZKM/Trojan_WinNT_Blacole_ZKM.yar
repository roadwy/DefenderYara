
rule Trojan_WinNT_Blacole_ZKM{
	meta:
		description = "Trojan:WinNT/Blacole_ZKM,SIGNATURE_TYPE_JAVAHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 10 00 bc 08 3a ?? 03 36 0a } //1
		$a_03_1 = {10 41 10 5a b6 ?? ?? 36 04 [0-2a] 10 41 a1 ff } //1
		$a_01_2 = {10 5a 36 0a 10 4d 36 } //1
		$a_01_3 = {a7 00 04 bf } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}