
rule Trojan_Linux_Necro_A_MTB{
	meta:
		description = "Trojan:Linux/Necro.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {33 48 78 44 00 68 00 68 d0 e9 0a 40 84 42 52 d0 33 48 df f8 c8 a0 78 44 df f8 bc b0 fa 44 05 68 fb 44 2c 48 78 44 07 68 } //01 00 
		$a_00_1 = {61 2e 61 6e 74 6c 61 75 6e 63 68 65 72 2e 63 6f 6d } //01 00  a.antlauncher.com
		$a_00_2 = {2f 64 61 74 61 2f 2e 61 6e 74 5f 63 68 65 63 6b 70 65 72 5f 64 69 72 2f 6b 65 79 73 74 6f 72 65 } //01 00  /data/.ant_checkper_dir/keystore
		$a_00_3 = {49 6e 6a 65 63 74 49 6e 74 65 72 66 61 63 65 } //01 00  InjectInterface
		$a_00_4 = {2f 6d 6e 74 2f 73 64 63 61 72 64 2f 44 6f 77 6e 6c 6f 61 64 2f 6b 69 6e 67 72 6f 6f 74 2e 61 70 6b 2e 74 6d 70 } //01 00  /mnt/sdcard/Download/kingroot.apk.tmp
		$a_00_5 = {67 5f 61 6e 74 52 65 73 70 6f 6e 73 65 } //00 00  g_antResponse
		$a_00_6 = {5d 04 00 } //00 67 
	condition:
		any of ($a_*)
 
}