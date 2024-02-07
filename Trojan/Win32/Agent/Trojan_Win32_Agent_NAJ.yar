
rule Trojan_Win32_Agent_NAJ{
	meta:
		description = "Trojan:Win32/Agent.NAJ,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3c 00 08 00 00 0a 00 "
		
	strings :
		$a_00_0 = {73 00 6f 00 63 00 69 00 65 00 64 00 61 00 64 00 65 00 5c 00 6e 00 6f 00 76 00 6f 00 20 00 70 00 72 00 6f 00 5c 00 6c 00 6f 00 61 00 64 00 65 00 72 00 43 00 72 00 69 00 70 00 74 00 56 00 42 00 5c 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //0a 00  sociedade\novo pro\loaderCriptVB\Loader.vbp
		$a_00_1 = {6e 00 65 00 74 00 73 00 68 00 20 00 66 00 69 00 72 00 65 00 77 00 61 00 6c 00 6c 00 20 00 61 00 64 00 64 00 20 00 61 00 6c 00 6c 00 6f 00 77 00 65 00 64 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //0a 00  netsh firewall add allowedprogram
		$a_00_2 = {59 6f 75 54 75 62 65 } //0a 00  YouTube
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_00_4 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //0a 00  ShellExecuteA
		$a_01_5 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00  MSVBVM60.DLL
		$a_00_6 = {46 00 74 00 70 00 2e 00 2e 00 2e 00 } //01 00  Ftp...
		$a_00_7 = {45 00 6d 00 6f 00 63 00 6f 00 65 00 73 00 5f 00 61 00 6c 00 65 00 67 00 72 00 69 00 61 00 } //00 00  Emocoes_alegria
	condition:
		any of ($a_*)
 
}