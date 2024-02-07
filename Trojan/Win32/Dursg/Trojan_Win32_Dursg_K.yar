
rule Trojan_Win32_Dursg_K{
	meta:
		description = "Trojan:Win32/Dursg.K,SIGNATURE_TYPE_PEHSTR_EXT,05 00 03 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 76 61 6c 75 65 20 69 64 3d 22 64 6f 77 6e 6c 6f 61 64 5f 55 52 4c 22 20 6e 75 6c 6c 3d 22 79 65 73 22 2f 3e } //01 00  <value id="download_URL" null="yes"/>
		$a_01_1 = {5f 74 6b 2e 6f 6c 64 } //01 00  _tk.old
		$a_01_2 = {22 20 72 6b 20 61 75 74 6f } //01 00  " rk auto
		$a_01_3 = {43 68 72 6f 6d 65 5f 75 70 64 61 74 65 72 } //01 00  Chrome_updater
		$a_01_4 = {53 63 72 69 70 74 55 70 64 61 74 65 3d } //01 00  ScriptUpdate=
		$a_01_5 = {54 54 69 62 69 61 4d 61 69 6e 54 68 72 65 61 64 } //01 00  TTibiaMainThread
		$a_01_6 = {64 6f 77 6e 6c 6f 61 64 5f 65 78 65 63 5f 66 69 6c 65 } //01 00  download_exec_file
		$a_01_7 = {67 65 74 66 69 6c 65 3d 31 } //00 00  getfile=1
	condition:
		any of ($a_*)
 
}