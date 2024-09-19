
rule Trojan_Win64_SystemBC_F{
	meta:
		description = "Trojan:Win64/SystemBC.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 83 ec 20 48 c7 c1 20 bf 02 00 } //1
		$a_01_1 = {48 83 ec 20 48 c7 c1 02 00 00 00 48 8d 57 52 4c 8b c7 ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}