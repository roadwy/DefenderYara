
rule Trojan_BAT_AgentTesla_TF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.TF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 76 34 2e 30 2e 33 30 33 31 39 5c 74 68 65 64 65 76 69 6c 63 6f 64 65 72 2e 65 78 65 } //01 00  C:\Windows\Microsoft.NET\Framework\v4.0.30319\thedevilcoder.exe
		$a_01_1 = {63 3a 5c 55 73 65 72 73 5c 56 49 43 54 4f 52 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 44 53 47 53 47 44 53 44 53 44 4c 4b 4a 53 44 4a 4b 5c 44 53 47 53 47 44 53 44 53 44 4c 4b 4a 53 44 4a 4b 5c 6f 62 6a 5c 44 65 62 75 67 5c 44 53 47 53 47 44 53 44 53 44 4c 4b 4a 53 44 4a 4b 2e 70 64 62 } //01 00  c:\Users\VICTOR\source\repos\DSGSGDSDSDLKJSDJK\DSGSGDSDSDLKJSDJK\obj\Debug\DSGSGDSDSDLKJSDJK.pdb
		$a_01_2 = {24 66 62 35 61 61 35 32 66 2d 39 66 37 65 2d 34 62 65 34 2d 62 63 61 64 2d 38 36 36 64 61 31 37 31 36 34 30 33 } //01 00  $fb5aa52f-9f7e-4be4-bcad-866da1716403
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_4 = {74 68 65 64 65 76 69 6c 63 6f 64 65 72 } //01 00  thedevilcoder
		$a_81_5 = {68 74 74 70 73 3a 23 23 74 65 70 69 64 6e 65 73 73 2d 74 75 65 73 64 61 79 73 2e 30 30 30 77 65 62 68 6f 73 74 61 70 70 2e 63 6f 6d 23 74 61 2e 65 78 65 } //00 00  https:##tepidness-tuesdays.000webhostapp.com#ta.exe
	condition:
		any of ($a_*)
 
}