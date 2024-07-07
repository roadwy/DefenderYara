
rule Trojan_Linux_SAgnt_A_xp{
	meta:
		description = "Trojan:Linux/SAgnt.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {48 89 e5 48 81 ec c0 00 00 00 48 89 bd 48 ff ff ff 48 89 b5 40 ff ff ff c7 45 fc 01 00 00 00 c7 45 f8 00 00 00 00 48 8d 95 50 ff ff ff 48 8b 85 48 ff ff ff 48 89 d6 48 89 c7 } //1
		$a_00_1 = {2e 30 00 77 72 69 74 65 00 72 65 61 64 00 5f 5f 65 72 72 6e 6f 5f 6c 6f 63 61 74 69 6f 6e 00 66 6f 72 6b 00 6c } //1
		$a_00_2 = {48 89 e5 48 83 ec 20 89 7d ec 48 89 75 e0 89 55 e8 c7 45 fc 00 00 00 00 c7 45 fc 00 00 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}