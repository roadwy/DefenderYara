
rule Trojan_Linux_GetShell_HAB_MTB{
	meta:
		description = "Trojan:Linux/GetShell.HAB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 62 69 6e 2f 62 61 73 68 00 52 53 48 20 54 45 53 54 20 45 4e 44 00 } //20
		$a_01_1 = {00 69 6e 65 74 5f 61 64 64 72 00 70 75 74 73 00 5f 5f 73 74 61 63 6b 5f 63 68 6b 5f 66 61 69 6c 00 73 6f 63 6b 65 74 00 64 75 70 32 00 65 78 65 63 76 65 00 5f 5f 6c 69 62 63 5f 73 74 61 72 74 5f 6d 61 69 6e 00 5f 5f 63 78 61 5f 66 69 6e 61 6c 69 7a 65 00 63 6f 6e 6e 65 63 74 00 6c 69 62 } //15 椀敮彴摡牤瀀瑵s彟瑳捡彫档彫慦汩猀捯敫t畤㉰攀數癣e彟楬换獟慴瑲浟楡n彟硣彡楦慮楬敺挀湯敮瑣氀扩
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=20
 
}