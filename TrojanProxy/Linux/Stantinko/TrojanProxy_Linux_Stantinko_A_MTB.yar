
rule TrojanProxy_Linux_Stantinko_A_MTB{
	meta:
		description = "TrojanProxy:Linux/Stantinko.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_00_0 = {70 72 6f 78 79 5f 69 70 3d } //1 proxy_ip=
		$a_00_1 = {2f 6b 62 64 6d 61 69 2f 44 52 54 49 50 52 4f 56 2f 69 6e 64 65 78 2e 70 68 70 } //2 /kbdmai/DRTIPROV/index.php
		$a_00_2 = {2f 6b 62 64 6d 61 69 2f 77 69 6e 73 76 63 2f 69 6e 64 65 78 2e 70 68 70 } //2 /kbdmai/winsvc/index.php
		$a_03_3 = {48 8b 45 f8 be ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 48 85 c0 74 1f 48 8b 45 f8 be ?? ?? ?? ?? 48 89 c7 e8 ?? ?? ?? ?? 48 85 c0 74 09 48 8b 05 ?? ?? ?? ?? eb 55 } //4
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_03_3  & 1)*4) >=9
 
}