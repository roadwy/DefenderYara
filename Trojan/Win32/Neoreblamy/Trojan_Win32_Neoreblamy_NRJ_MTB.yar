
rule Trojan_Win32_Neoreblamy_NRJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 49 00 8a 44 0b ff 30 04 0b 49 83 f9 02 } //1
		$a_01_1 = {4d 61 63 5c 48 6f 6d 65 5c 44 6f 63 75 6d 65 6e 74 73 5c 4d 4d 50 5c 6d 6d 70 5f 73 65 72 76 65 72 5f 73 74 75 66 66 5c 73 74 75 66 66 5c 64 69 73 74 72 69 62 5f 73 65 72 76 65 72 5c 73 66 78 5c 45 78 65 52 65 73 74 6f 72 65 72 5c 52 65 6c 65 61 73 65 5c 45 78 65 52 65 73 74 6f 72 65 72 2e 70 64 62 } //2 Mac\Home\Documents\MMP\mmp_server_stuff\stuff\distrib_server\sfx\ExeRestorer\Release\ExeRestorer.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}