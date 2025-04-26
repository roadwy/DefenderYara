
rule Trojan_Win64_Winnti_J_dha{
	meta:
		description = "Trojan:Win64/Winnti.J!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 00 65 00 76 00 69 00 63 00 65 00 5c 00 50 00 4e 00 54 00 46 00 49 00 4c 00 54 00 45 00 52 00 } //3 Device\PNTFILTER
		$a_03_1 = {eb 53 48 8b 05 ?? ?? 00 00 8b 00 25 ff ff 00 00 3d b1 1d 00 00 73 0a c7 44 24 ?? 01 00 00 00 eb 08 } //4
		$a_01_2 = {44 00 72 00 69 00 76 00 65 00 72 00 5c 00 6e 00 73 00 69 00 70 00 72 00 6f 00 78 00 79 00 } //1 Driver\nsiproxy
		$a_01_3 = {44 00 65 00 76 00 69 00 63 00 65 00 5c 00 54 00 63 00 70 00 } //1 Device\Tcp
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}